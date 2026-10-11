//! Real bolt file-format compatibility for `cache.db`.
//!
//! The format keeps buckets in a copy-on-write B+tree over a memory-mapped file with two meta
//! pages, magic `0xED0CDAED`, format version 2, and an FNV-64a checksum over each meta page's
//! fixed-size header. The behaviour the cachefile module relies on is kept — durable
//! buckets of key/value pairs, write transactions that roll back on failure, ordered cursors —
//! over an in-memory `BTreeMap`, but it now reads and writes the real bolt page layout: two meta
//! pages, a freelist page, leaf and branch pages with overflow pages for oversized entries, and
//! inline or non-inline sub-buckets. An existing `cache.db` in that layout is read intact instead
//! of being deleted, and a file written here opens correctly in a bolt reader.
//!
//! Every write still rewrites the whole bucket tree (`write_bucket` below always emits non-inline
//! pages, even ones small enough to be inlined; both layouts are valid bolt files) but,
//! like the format itself, it happens in place through the single locked handle `Db::open` keeps for
//! the `Db`'s whole life: the new tree and a fresh freelist are allocated from pages the live
//! meta's tree cannot reach — the generation two commits back, whose meta slot this commit is
//! about to overwrite, plus any prior leftover — extending the file only once that pool runs out.
//! Nothing the live meta can reach is ever touched, so a crash at any point before the final fsync
//! leaves the file exactly as valid as before the write started; `select_meta` below already
//! prefers the meta with the higher valid transaction id, so the untouched live meta is always the
//! one a reader sees. `State::live`/`State::free` (below) carry this generation-by-generation
//! bookkeeping; there is no rename and so no window where the path could resolve to a different
//! inode than the one this `Db` locked.
//!
//! `cache.db` is opened once and locked exclusively for the `Db`'s whole lifetime; every read and
//! write goes through that same handle (`Db::open` reads the file's current contents off it
//! directly, never by reopening the path). The lock matches the `flock` on Unix
//! via `std::fs::File::try_lock`, retried every 50ms until `Options::timeout` elapses
//! (`Error::Timeout`, the `"timeout"`). On Windows, the `LockFileEx` locks
//! exactly one byte at offset `2^64-1`; `std::fs::File::try_lock` instead
//! locks the whole file, so it never contends with a bolt lock on that one-byte range. Windows here
//! calls `windows-sys`'s `LockFileEx` directly on that same one-byte range. The lock is released by
//! `Db::close` or `Drop`; nothing else ever clears it.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Bound::{Excluded, Unbounded};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

pub const MAX_KEY_SIZE: usize = 32768;
pub const MAX_VALUE_SIZE: usize = (1 << 31) - 2;

const BOLT_MAGIC: u32 = 0xED0C_DAED;
const BOLT_VERSION: u32 = 2;
/// The default page size on the platforms this crate targets.
const DEFAULT_PAGE_SIZE: usize = 4096;

const PAGE_HEADER_SIZE: usize = 16;
/// The leaf and branch element sizes (both 16 bytes).
const LEAF_ELEM_SIZE: usize = 16;
const BRANCH_ELEM_SIZE: usize = 16;
const BUCKET_HEADER_SIZE: usize = 16;
/// Size, in bytes, of the meta struct.
const META_SIZE: usize = 64;
/// Offset of the checksum within the struct; the hash covers everything before it.
const META_CHECKSUM_OFFSET: usize = 56;

/// The branch, leaf, meta and freelist page flags.
const PAGE_FLAG_BRANCH: u16 = 0x01;
const PAGE_FLAG_LEAF: u16 = 0x02;
const PAGE_FLAG_META: u16 = 0x04;
const PAGE_FLAG_FREELIST: u16 = 0x10;

/// Set on a leaf element whose value is a nested bucket header.
const BUCKET_LEAF_FLAG: u32 = 0x01;

/// Fixed page id every commit's own freelist page allocates from.
const FREELIST_PAGE_ID: u64 = 2;
/// Only `encode_tree` (a test helper for the raw page format) still uses this fixed layout.
#[cfg(test)]
const FIRST_CONTENT_PAGE_ID: u64 = 3;

/// Recursion guard for malformed or cyclic on-disk trees.
const MAX_TREE_DEPTH: u32 = 64;

pub type Buckets = BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>>;

/// The sentinel errors, keeping the bolt messages verbatim.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid database")]
    Invalid,
    #[error("checksum error")]
    Checksum,
    #[error("version mismatch")]
    VersionMismatch,
    #[error("timeout")]
    Timeout,
    #[error("database not open")]
    DatabaseNotOpen,
    #[error("bucket not found")]
    BucketNotFound,
    #[error("bucket name required")]
    BucketNameRequired,
    #[error("key required")]
    KeyRequired,
    #[error("key too large")]
    KeyTooLarge,
    #[error("value too large")]
    ValueTooLarge,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The three kinds of failed meta-page validation.
#[derive(Clone, Copy, Debug)]
enum MetaError {
    Invalid,
    VersionMismatch,
    Checksum,
}

impl From<MetaError> for Error {
    fn from(err: MetaError) -> Self {
        match err {
            MetaError::Invalid => Self::Invalid,
            MetaError::VersionMismatch => Self::VersionMismatch,
            MetaError::Checksum => Self::Checksum,
        }
    }
}

/// The options, limited to the fields the cachefile module sets.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub timeout: Option<Duration>,
    pub no_statistics: bool,
}

#[derive(Debug)]
pub struct Db {
    path: PathBuf,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    buckets: Buckets,
    closed: bool,
    page_size: usize,
    txid: u64,
    /// The next unallocated page id. Every commit allocates this generation's
    /// content and freelist pages starting here once `free` runs out.
    next_pgid: u64,
    /// Pages reachable from the live meta's tree and freelist as of the last successful commit;
    /// `commit_in_place` never touches these, and they only become reusable once *this* commit's
    /// own write makes them stale for the one after it.
    live: Vec<u64>,
    /// Pages not reachable from the live meta — what the next commit's allocator reuses before
    /// extending the file, mirroring the format's own freelist.
    free: Vec<u64>,
    /// Held for `Db`'s whole lifetime; released by `Db::close` or `Drop`. Every read and write to
    /// `cache.db` goes through this single handle.
    file: Option<LockedFile>,
}

impl Db {
    /// Also creates the file when it is missing or empty.
    pub fn open(path: &str, mode: u32, options: &Options) -> Result<Self, Error> {
        let path = PathBuf::from(path);
        let lock = LockedFile::open_and_acquire(&path, mode, options.timeout)?;
        let data = lock.read_all()?;

        let mut state = if data.is_empty() {
            State {
                buckets: Buckets::new(),
                closed: false,
                page_size: DEFAULT_PAGE_SIZE,
                txid: 0,
                next_pgid: 0,
                live: Vec::new(),
                free: Vec::new(),
                file: Some(lock),
            }
        } else {
            let (buckets, page_size, txid, next_pgid, live) = decode(&data)?;
            let live_set: HashSet<u64> = live.iter().copied().collect();
            let free: Vec<u64> = (FREELIST_PAGE_ID..next_pgid).filter(|id| !live_set.contains(id)).collect();
            State { buckets, closed: false, page_size, txid, next_pgid, live, free, file: Some(lock) }
        };

        if data.is_empty() {
            let (bytes, next_pgid) = build_initial_file(state.page_size, &state.buckets);
            let file = state.file.as_ref().ok_or(Error::DatabaseNotOpen)?;
            file.write_at(0, &bytes)?;
            file.sync()?;
            state.txid = 1;
            state.next_pgid = next_pgid;
            state.live = (FREELIST_PAGE_ID..next_pgid).collect();
        }
        Ok(Self { path, state: Mutex::new(state) })
    }

    pub fn path(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// Every commit is already durable, so only the lock and handle are released.
    pub fn close(&self) -> Result<(), Error> {
        let mut state = self.state.lock();
        if state.closed {
            return Err(Error::DatabaseNotOpen);
        }
        state.closed = true;
        state.file = None;
        drop(state);
        Ok(())
    }

    /// The state is restored when the closure (or the write) fails and the
    /// file is written in place, through the locked handle, when it succeeds.
    pub fn batch(&self, f: impl FnOnce(&mut Tx<'_>) -> anyhow::Result<()>) -> anyhow::Result<()> {
        let mut guard = self.state.lock();
        if guard.closed {
            return Err(Error::DatabaseNotOpen.into());
        }

        let backup = guard.buckets.clone();
        let result = {
            let mut tx = Tx { buckets: &mut guard.buckets };
            f(&mut tx)
        };
        if let Err(err) = result {
            guard.buckets = backup;
            return Err(err);
        }

        let next_txid = guard.txid + 1;
        let state = &mut *guard;
        let file = state.file.as_ref().ok_or(Error::DatabaseNotOpen)?;
        match commit_in_place(
            file,
            &state.buckets,
            state.page_size,
            next_txid,
            state.next_pgid,
            &state.free,
            &state.live,
        ) {
            Ok((next_pgid, free, live)) => {
                state.txid = next_txid;
                state.next_pgid = next_pgid;
                state.free = free;
                state.live = live;
            }
            Err(err) => {
                state.buckets = backup;
                return Err(err.into());
            }
        }
        drop(guard);
        Ok(())
    }

    pub fn view(&self, f: impl FnOnce(&mut Tx<'_>) -> anyhow::Result<()>) -> anyhow::Result<()> {
        let mut state = self.state.lock();
        if state.closed {
            return Err(Error::DatabaseNotOpen.into());
        }
        let result = f(&mut Tx { buckets: &mut state.buckets });
        drop(state);
        result
    }
}

#[derive(Debug)]
pub struct Tx<'a> {
    buckets: &'a mut Buckets,
}

impl Tx<'_> {
    pub fn create_bucket_if_not_exists(&mut self, name: &[u8]) -> Result<Bucket<'_>, Error> {
        if name.is_empty() {
            return Err(Error::BucketNameRequired);
        }
        Ok(Bucket { entries: self.buckets.entry(name.to_vec()).or_default() })
    }

    pub fn bucket(&mut self, name: &[u8]) -> Option<Bucket<'_>> {
        self.buckets.get_mut(name).map(|entries| Bucket { entries })
    }

    pub fn delete_bucket(&mut self, name: &[u8]) -> Result<(), Error> {
        if self.buckets.remove(name).is_none() {
            return Err(Error::BucketNotFound);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Bucket<'a> {
    entries: &'a mut BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Bucket<'_> {
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        if key.is_empty() {
            return Err(Error::KeyRequired);
        }
        if key.len() > MAX_KEY_SIZE {
            return Err(Error::KeyTooLarge);
        }
        if value.len() > MAX_VALUE_SIZE {
            return Err(Error::ValueTooLarge);
        }
        self.entries.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries.get(key).map(Vec::as_slice)
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.entries.remove(key);
        Ok(())
    }

    /// Walks the bucket in key order.
    #[must_use]
    pub const fn cursor(&self) -> Cursor<'_> {
        Cursor { entries: self.entries, current: None }
    }
}

#[derive(Debug)]
pub struct Cursor<'a> {
    entries: &'a BTreeMap<Vec<u8>, Vec<u8>>,
    current: Option<&'a Vec<u8>>,
}

impl<'a> Cursor<'a> {
    pub fn first(&mut self) -> Option<(&'a [u8], &'a [u8])> {
        self.current = self.entries.keys().next();
        self.value()
    }

    /// Keeps the `next` name rather than implementing `Iterator`.
    #[expect(
        clippy::should_implement_trait,
        reason = "the `next` name is kept rather than implementing `Iterator`"
    )]
    pub fn next(&mut self) -> Option<(&'a [u8], &'a [u8])> {
        let current = self.current?;
        self.current = self.entries.range::<Vec<u8>, _>((Excluded(current), Unbounded)).next().map(|(key, _)| key);
        self.value()
    }

    fn value(&self) -> Option<(&'a [u8], &'a [u8])> {
        let key = self.current?;
        let value = self.entries.get(key)?;
        Some((key.as_slice(), value.as_slice()))
    }
}

const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(50);

#[cfg(unix)]
fn open_db_file(path: &Path, mode: u32) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(mode).open(path)
}

#[cfg(windows)]
fn open_db_file(path: &Path, mode: u32) -> io::Result<File> {
    let _ = mode;
    fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_db_file(path: &Path, mode: u32) -> io::Result<File> {
    let _ = mode;
    fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)
}

/// A single, non-blocking, non-retried exclusive-lock attempt (`flock(2)`, `LOCK_EX | LOCK_NB`,
/// via `std::fs::File::try_lock`).
#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    use std::fs::TryLockError;

    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(TryLockError::WouldBlock) => Ok(false),
        Err(TryLockError::Error(err)) => Err(err),
    }
}

/// The same attempt on Windows, but on the bolt lock's exact byte range: `std::fs::File::try_lock` locks
/// the whole file (offset 0, length `u64::MAX`), while a bolt lock covers exactly
/// one byte at offset `u64::MAX`. The two ranges never overlap, so only
/// locking this exact range lets another bolt implementation and this one exclude each other.
#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "`LockFileEx` is only reachable through `unsafe`; there is no safe std equivalent for a byte-range lock"
)]
fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let mut overlapped = OVERLAPPED::default();
    overlapped.Anonymous.Anonymous.Offset = u32::MAX;
    overlapped.Anonymous.Anonymous.OffsetHigh = u32::MAX;

    // SAFETY: `file` outlives this call, so its raw handle stays valid for its duration;
    // `overlapped` is a fully initialized, stack-local `OVERLAPPED`.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &raw mut overlapped,
        )
    };
    if ok != 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(i32::try_from(ERROR_LOCK_VIOLATION).unwrap_or(i32::MAX)) {
        Ok(false)
    } else {
        Err(err)
    }
}

#[cfg(not(any(unix, windows)))]
fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    use std::fs::TryLockError;

    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(TryLockError::WouldBlock) => Ok(false),
        Err(TryLockError::Error(err)) => Err(err),
    }
}

/// `cache.db`'s single open, exclusively locked handle: every read and write for the `Db`'s whole
/// lifetime goes through it. Dropping it closes the handle, which releases every lock held
/// through it on both Unix and Windows.
#[derive(Debug)]
struct LockedFile(File);

impl LockedFile {
    /// Opens (creating if missing) and exclusively locks `path`'s current inode, retried every
    /// `LOCK_RETRY_INTERVAL` until `timeout` elapses (`None` retries forever, matching the
    /// `timeout == 0`).
    fn open_and_acquire(path: &Path, mode: u32, timeout: Option<Duration>) -> Result<Self, Error> {
        let file = open_db_file(path, mode)?;
        let start = Instant::now();
        loop {
            if try_lock_exclusive(&file)? {
                return Ok(Self(file));
            }
            if let Some(timeout) = timeout {
                if start.elapsed() + LOCK_RETRY_INTERVAL >= timeout {
                    return Err(Error::Timeout);
                }
            }
            std::thread::sleep(LOCK_RETRY_INTERVAL);
        }
    }

    fn read_all(&self) -> io::Result<Vec<u8>> {
        let mut file = &self.0;
        file.seek(SeekFrom::Start(0))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut file = &self.0;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)
    }

    fn sync(&self) -> io::Result<()> {
        self.0.sync_all()
    }
}

fn tree_from_buckets(buckets: &Buckets) -> BTreeMap<Vec<u8>, Entry> {
    let mut root = BTreeMap::new();
    for (name, entries) in buckets {
        let inner = entries.iter().map(|(key, value)| (key.clone(), Entry::Value(value.clone()))).collect();
        root.insert(name.clone(), Entry::Bucket(inner));
    }
    root
}

/// Meta page 0 at txid 0 and meta page 1 at txid 1, otherwise identical, an
/// empty freelist at page 2, and `buckets`' (normally empty) initial tree from page 3. Returns the
/// encoded bytes and the next unallocated page id.
fn build_initial_file(page_size: usize, buckets: &Buckets) -> (Vec<u8>, u64) {
    let root = tree_from_buckets(buckets);
    let mut writer = PageWriter::new(page_size, FREELIST_PAGE_ID, Vec::new());
    let freelist_pgid = write_freelist_page(&mut writer, &[]);
    let db_root = write_bucket(&mut writer, &root);
    let next_pgid = writer.next_id;

    let mut file = vec![0u8; 2 * page_size];
    for (page, (slot, txid)) in file.chunks_exact_mut(page_size).zip([(0u64, 0u64), (1, 1)]) {
        write_page_header(page, slot, PAGE_FLAG_META, 0, 0);
        write_meta(page, wire_u32(page_size), db_root, 0, freelist_pgid, next_pgid, txid);
    }
    for (_, bytes) in &writer.regions {
        file.extend_from_slice(bytes);
    }
    (file, next_pgid)
}

/// Writes one commit in place through `file`'s single locked handle, as the format does: the new tree
/// and freelist are allocated from `free` first — pages the live meta's tree cannot reach, so
/// touching them cannot corrupt it — extending past `next_pgid` only once that pool is exhausted.
/// `live` (this generation's own pages, going in) only becomes reusable for the commit *after*
/// this one; see the module doc for why that is always safe. Returns the new high-water mark, the
/// pages now free for the next commit, and this commit's own live set.
fn commit_in_place(
    file: &LockedFile,
    buckets: &Buckets,
    page_size: usize,
    txid: u64,
    next_pgid: u64,
    free: &[u64],
    live: &[u64],
) -> Result<(u64, Vec<u64>, Vec<u64>), Error> {
    let root = tree_from_buckets(buckets);
    let mut writer = PageWriter::new(page_size, next_pgid, free.to_vec());
    let db_root = write_bucket(&mut writer, &root);

    // Sized from what would be free if the freelist page took nothing; reusing one of those
    // pages for its own storage only ever shrinks the list actually written, never invalidates
    // this page count.
    let candidate_len = writer.free.len() + live.len();
    let freelist_page_count = freelist_page_count(page_size, candidate_len);
    let (freelist_pgid, freelist_idx) = writer.alloc(freelist_page_count);

    let mut new_free: Vec<u64> = writer.free.iter().copied().chain(live.iter().copied()).collect();
    new_free.sort_unstable();
    fill_freelist_page(writer.page_mut(freelist_idx), freelist_pgid, freelist_page_count, &new_free);

    let new_pgid = writer.next_id;
    let mut new_live: Vec<u64> = writer
        .regions
        .iter()
        .flat_map(|(start, bytes)| {
            let count = (bytes.len() / page_size) as u64;
            *start..*start + count
        })
        .collect();
    new_live.sort_unstable();

    for (start, bytes) in &writer.regions {
        file.write_at(*start * page_size as u64, bytes)?;
    }
    file.sync()?;

    let meta_slot = txid % 2;
    let mut meta_page = vec![0u8; page_size];
    write_page_header(&mut meta_page, meta_slot, PAGE_FLAG_META, 0, 0);
    write_meta(&mut meta_page, wire_u32(page_size), db_root, 0, freelist_pgid, new_pgid, txid);
    file.write_at(meta_slot * page_size as u64, &meta_page)?;
    file.sync()?;

    Ok((new_pgid, new_free, new_live))
}

/// A bucket's contents once flattened off (or before being laid out onto) bolt pages: a plain
/// value, or a nested bucket. The two-level `Buckets` model cachefile uses never nests, but the
/// on-disk engine below is a general bolt bucket tree, so a file with real nesting
/// still parses correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Value(Vec<u8>),
    Bucket(BTreeMap<Vec<u8>, Self>),
}

fn fnv64a(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

// ---- writer -----------------------------------------------------------------------------------

struct PageWriter {
    page_size: usize,
    next_id: u64,
    /// Sorted ascending; pages not reachable from the live meta, reused before extending.
    free: Vec<u64>,
    regions: Vec<(u64, Vec<u8>)>,
}

impl PageWriter {
    fn new(page_size: usize, next_id: u64, free: Vec<u64>) -> Self {
        Self { page_size, next_id, free, regions: Vec::new() }
    }

    /// The lowest index and first id of a run of `page_count` consecutive free ids, if one exists;
    /// overflow pages need contiguous ids like the format's own mmap layout requires.
    fn find_contiguous_free(&self, page_count: usize) -> Option<(usize, u64)> {
        if page_count == 0 || self.free.len() < page_count {
            return None;
        }
        self.free.windows(page_count).enumerate().find_map(|(idx, run)| {
            let first = *run.first()?;
            (*run.last()? == first + (page_count as u64 - 1)).then_some((idx, first))
        })
    }

    fn alloc(&mut self, page_count: usize) -> (u64, usize) {
        let id = if let Some((idx, id)) = self.find_contiguous_free(page_count) {
            self.free.drain(idx..idx + page_count);
            id
        } else {
            let id = self.next_id;
            self.next_id += page_count as u64;
            id
        };
        let idx = self.regions.len();
        self.regions.push((id, vec![0u8; page_count * self.page_size]));
        (id, idx)
    }

    fn page_mut(&mut self, idx: usize) -> &mut [u8] {
        match self.regions.get_mut(idx) {
            Some((_, bytes)) => bytes.as_mut_slice(),
            None => &mut [],
        }
    }
}

/// Copies `bytes` into `dst` at `offset`, leaving a destination that stops short untouched.
fn put_bytes(dst: &mut [u8], offset: usize, bytes: &[u8]) {
    if let Some(slot) = dst.get_mut(offset..offset + bytes.len()) {
        slot.copy_from_slice(bytes);
    }
}

/// The `[start, end)` window of `items`.
fn subslice<T>(items: &[T], start: usize, end: usize) -> &[T] {
    let (_, tail) = items.split_at(start);
    tail.split_at(end - start).0
}

/// The low 16 bits of `value`, the page-header entry count.
#[expect(clippy::cast_possible_truncation, reason = "the page header stores the entry count in 16 bits")]
fn wire_u16(value: usize) -> u16 {
    value as u16
}

/// The low 32 bits of `value`, the element offset and size fields.
#[expect(clippy::cast_possible_truncation, reason = "element offsets and sizes are stored in 32-bit fields")]
fn wire_u32(value: usize) -> u32 {
    value as u32
}

fn write_page_header(page: &mut [u8], id: u64, flags: u16, count: u16, overflow: u32) {
    put_bytes(page, 0, &id.to_le_bytes());
    put_bytes(page, 8, &flags.to_le_bytes());
    put_bytes(page, 10, &count.to_le_bytes());
    put_bytes(page, 12, &overflow.to_le_bytes());
}

/// The split floor: a run may close only once it already holds this many entries.
const MIN_KEYS_PER_PAGE: usize = 2;

/// Splits `sizes` (each entry's on-page footprint, header excluded) into page-sized runs, greedily
/// closing a run only when the next entry would overflow it. A run exceeding the page becomes an
/// overflow page at write time. Zero entries still yields one (empty) run, so an empty bucket gets
/// a real, empty leaf page.
///
/// The `MIN_KEYS_PER_PAGE` floor matters when entries are larger than half a page: without it, a
/// run of such entries closes after every single one, so the branch level built from the output
/// has exactly as many entries as the one below it and `write_branch_level`'s recursion never
/// terminates. With the floor, every run but the last one consumes at least two entries, so each
/// pass strictly shrinks the level.
fn chunk_ranges(page_size: usize, sizes: &[usize]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0usize;
    let mut size = PAGE_HEADER_SIZE;
    let mut count = 0usize;
    for (i, &item) in sizes.iter().enumerate() {
        if count >= MIN_KEYS_PER_PAGE && size + item > page_size {
            ranges.push((start, i));
            start = i;
            size = PAGE_HEADER_SIZE;
            count = 0;
        }
        size += item;
        count += 1;
    }
    ranges.push((start, sizes.len()));
    ranges
}

fn write_leaf_page(w: &mut PageWriter, entries: &[(Vec<u8>, u32, Vec<u8>)]) -> u64 {
    let data_len: usize = entries.iter().map(|(key, _, value)| key.len() + value.len()).sum();
    let total = PAGE_HEADER_SIZE + entries.len() * LEAF_ELEM_SIZE + data_len;
    let page_count = total.div_ceil(w.page_size).max(1);
    let (id, idx) = w.alloc(page_count);
    let page = w.page_mut(idx);
    write_page_header(page, id, PAGE_FLAG_LEAF, wire_u16(entries.len()), wire_u32(page_count - 1));

    let mut data_off = PAGE_HEADER_SIZE + entries.len() * LEAF_ELEM_SIZE;
    for (i, (key, flags, value)) in entries.iter().enumerate() {
        let elem_off = PAGE_HEADER_SIZE + i * LEAF_ELEM_SIZE;
        put_bytes(page, elem_off, &flags.to_le_bytes());
        put_bytes(page, elem_off + 4, &wire_u32(data_off - elem_off).to_le_bytes());
        put_bytes(page, elem_off + 8, &wire_u32(key.len()).to_le_bytes());
        put_bytes(page, elem_off + 12, &wire_u32(value.len()).to_le_bytes());
        put_bytes(page, data_off, key);
        put_bytes(page, data_off + key.len(), value);
        data_off += key.len() + value.len();
    }
    id
}

fn write_branch_page(w: &mut PageWriter, children: &[(Vec<u8>, u64)]) -> u64 {
    let data_len: usize = children.iter().map(|(key, _)| key.len()).sum();
    let total = PAGE_HEADER_SIZE + children.len() * BRANCH_ELEM_SIZE + data_len;
    let page_count = total.div_ceil(w.page_size).max(1);
    let (id, idx) = w.alloc(page_count);
    let page = w.page_mut(idx);
    write_page_header(page, id, PAGE_FLAG_BRANCH, wire_u16(children.len()), wire_u32(page_count - 1));

    let mut data_off = PAGE_HEADER_SIZE + children.len() * BRANCH_ELEM_SIZE;
    for (i, (key, pgid)) in children.iter().enumerate() {
        let elem_off = PAGE_HEADER_SIZE + i * BRANCH_ELEM_SIZE;
        put_bytes(page, elem_off, &wire_u32(data_off - elem_off).to_le_bytes());
        put_bytes(page, elem_off + 4, &wire_u32(key.len()).to_le_bytes());
        put_bytes(page, elem_off + 8, &pgid.to_le_bytes());
        put_bytes(page, data_off, key);
        data_off += key.len();
    }
    id
}

fn write_leaf_level(w: &mut PageWriter, entries: &[(Vec<u8>, u32, Vec<u8>)]) -> u64 {
    let sizes: Vec<usize> = entries.iter().map(|(key, _, value)| LEAF_ELEM_SIZE + key.len() + value.len()).collect();
    let mut children = Vec::new();
    for (start, end) in chunk_ranges(w.page_size, &sizes) {
        let chunk = subslice(entries, start, end);
        let id = write_leaf_page(w, chunk);
        children.push((chunk.first().map_or_else(Vec::new, |(key, _, _)| key.clone()), id));
    }
    write_branch_level(w, &children)
}

fn write_branch_level(w: &mut PageWriter, children: &[(Vec<u8>, u64)]) -> u64 {
    if let [child] = children {
        return child.1;
    }
    let sizes: Vec<usize> = children.iter().map(|(key, _)| BRANCH_ELEM_SIZE + key.len()).collect();
    let ranges = chunk_ranges(w.page_size, &sizes);
    if let &[(start, end)] = ranges.as_slice() {
        return write_branch_page(w, subslice(children, start, end));
    }
    let mut next = Vec::new();
    for (start, end) in ranges {
        let chunk = subslice(children, start, end);
        let id = write_branch_page(w, chunk);
        next.push((chunk.first().map_or_else(Vec::new, |(key, _)| key.clone()), id));
    }
    write_branch_level(w, &next)
}

fn write_bucket(w: &mut PageWriter, entries: &BTreeMap<Vec<u8>, Entry>) -> u64 {
    let mut leaf_entries = Vec::with_capacity(entries.len());
    for (key, entry) in entries {
        match entry {
            Entry::Value(value) => leaf_entries.push((key.clone(), 0u32, value.clone())),
            Entry::Bucket(children) => {
                let child_root = write_bucket(w, children);
                let mut value = Vec::with_capacity(BUCKET_HEADER_SIZE);
                value.extend_from_slice(&child_root.to_le_bytes());
                value.extend_from_slice(&0u64.to_le_bytes());
                leaf_entries.push((key.clone(), BUCKET_LEAF_FLAG, value));
            }
        }
    }
    write_leaf_level(w, &leaf_entries)
}

fn write_meta(page: &mut [u8], page_size: u32, root_pgid: u64, root_seq: u64, freelist: u64, pgid: u64, txid: u64) {
    let base = PAGE_HEADER_SIZE;
    put_bytes(page, base, &BOLT_MAGIC.to_le_bytes());
    put_bytes(page, base + 4, &BOLT_VERSION.to_le_bytes());
    put_bytes(page, base + 8, &page_size.to_le_bytes());
    put_bytes(page, base + 12, &0u32.to_le_bytes());
    put_bytes(page, base + 16, &root_pgid.to_le_bytes());
    put_bytes(page, base + 24, &root_seq.to_le_bytes());
    put_bytes(page, base + 32, &freelist.to_le_bytes());
    put_bytes(page, base + 40, &pgid.to_le_bytes());
    put_bytes(page, base + 48, &txid.to_le_bytes());
    let checksum = fnv64a(subslice(page, base, base + META_CHECKSUM_OFFSET));
    put_bytes(page, base + META_CHECKSUM_OFFSET, &checksum.to_le_bytes());
}

/// An array-format freelist page: a plain header plus
/// `ids.len()` little-endian `u64`s, no per-element table. `ids.len() >= 0xFFFF` stores the true
/// count in the first `u64` and sets the header count to `0xFFFF`.
fn freelist_page_count(page_size: usize, ids_len: usize) -> usize {
    let overflow_count = ids_len >= 0xFFFF;
    let stored = if overflow_count { ids_len + 1 } else { ids_len };
    (PAGE_HEADER_SIZE + stored * 8).div_ceil(page_size).max(1)
}

fn fill_freelist_page(page: &mut [u8], id: u64, page_count: usize, ids: &[u64]) {
    let overflow_count = ids.len() >= 0xFFFF;
    let count = if overflow_count { 0xFFFF } else { wire_u16(ids.len()) };
    write_page_header(page, id, PAGE_FLAG_FREELIST, count, wire_u32(page_count - 1));

    let start = if overflow_count {
        put_bytes(page, PAGE_HEADER_SIZE, &(ids.len() as u64).to_le_bytes());
        1
    } else {
        0
    };
    for (i, &pgid) in ids.iter().enumerate() {
        put_bytes(page, PAGE_HEADER_SIZE + (start + i) * 8, &pgid.to_le_bytes());
    }
}

/// Convenience for callers that already know the final id list (`build_initial_file`, tests):
/// `commit_in_place` instead allocates the freelist's own storage before it knows the final list
/// (see there for why) and calls `fill_freelist_page` directly.
fn write_freelist_page(w: &mut PageWriter, ids: &[u64]) -> u64 {
    let page_count = freelist_page_count(w.page_size, ids.len());
    let (id, idx) = w.alloc(page_count);
    fill_freelist_page(w.page_mut(idx), id, page_count, ids);
    id
}

/// Test-only helper for exercising the raw page format directly; production writes go through
/// `build_initial_file`/`commit_in_place` instead.
#[cfg(test)]
fn encode_tree(root: &BTreeMap<Vec<u8>, Entry>, page_size: usize, txid: u64) -> Vec<u8> {
    let mut writer = PageWriter::new(page_size, FIRST_CONTENT_PAGE_ID, Vec::new());
    let db_root = write_bucket(&mut writer, root);
    let pgid_high_water = writer.next_id;

    let mut file = vec![0u8; 3 * page_size];
    write_page_header(&mut file[0..page_size], 0, PAGE_FLAG_META, 0, 0);
    write_meta(&mut file[0..page_size], page_size as u32, db_root, 0, FREELIST_PAGE_ID, pgid_high_water, txid);
    write_page_header(&mut file[page_size..2 * page_size], 1, PAGE_FLAG_META, 0, 0);
    write_meta(
        &mut file[page_size..2 * page_size],
        page_size as u32,
        db_root,
        0,
        FREELIST_PAGE_ID,
        pgid_high_water,
        txid,
    );
    write_page_header(&mut file[2 * page_size..3 * page_size], FREELIST_PAGE_ID, PAGE_FLAG_FREELIST, 0, 0);

    for (_, bytes) in &writer.regions {
        file.extend_from_slice(bytes);
    }
    file
}

#[cfg(test)]
fn encode(buckets: &Buckets, page_size: usize, txid: u64) -> Vec<u8> {
    encode_tree(&tree_from_buckets(buckets), page_size, txid)
}

// ---- reader -------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct MetaInfo {
    page_size: usize,
    root_pgid: u64,
    txid: u64,
    /// The next unallocated page id (see `commit_in_place`'s doc).
    pgid: u64,
    freelist: u64,
}

/// Reads a little-endian `u16` at `offset`, or `None` when the slice is too short.
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)?.try_into().ok().map(u16::from_le_bytes)
}

/// Reads a little-endian `u32` at `offset`, or `None` when the slice is too short.
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)?.try_into().ok().map(u32::from_le_bytes)
}

/// Reads a little-endian `u64` at `offset`, or `None` when the slice is too short.
fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)?.try_into().ok().map(u64::from_le_bytes)
}

/// `id`'s byte offset in the file, or `None` when the id or the offset does not fit a `usize`.
fn page_offset(page_size: usize, id: u64) -> Option<usize> {
    usize::try_from(id).ok()?.checked_mul(page_size)
}

fn parse_meta_page(page: &[u8]) -> Result<MetaInfo, MetaError> {
    let header = page.get(0..PAGE_HEADER_SIZE).ok_or(MetaError::Invalid)?;
    let flags = read_u16(header, 8).ok_or(MetaError::Invalid)?;
    if flags != PAGE_FLAG_META {
        return Err(MetaError::Invalid);
    }
    let meta = page.get(PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + META_SIZE).ok_or(MetaError::Invalid)?;
    let magic = read_u32(meta, 0).ok_or(MetaError::Invalid)?;
    if magic != BOLT_MAGIC {
        return Err(MetaError::Invalid);
    }
    let version = read_u32(meta, 4).ok_or(MetaError::Invalid)?;
    if version != BOLT_VERSION {
        return Err(MetaError::VersionMismatch);
    }
    let checksum = read_u64(meta, 56).ok_or(MetaError::Invalid)?;
    if fnv64a(subslice(meta, 0, META_CHECKSUM_OFFSET)) != checksum {
        return Err(MetaError::Checksum);
    }
    let page_size = read_u32(meta, 8).ok_or(MetaError::Invalid)? as usize;
    if !page_size.is_power_of_two() || !(512..=(1 << 20)).contains(&page_size) {
        return Err(MetaError::Invalid);
    }
    let root_pgid = read_u64(meta, 16).ok_or(MetaError::Invalid)?;
    let freelist = read_u64(meta, 32).ok_or(MetaError::Invalid)?;
    let pgid = read_u64(meta, 40).ok_or(MetaError::Invalid)?;
    let txid = read_u64(meta, 48).ok_or(MetaError::Invalid)?;
    Ok(MetaInfo { page_size, root_pgid, txid, pgid, freelist })
}

/// Prefers the meta page with the higher valid transaction id, falling back to
/// the other if that one fails validation; if both fail, the first meta page's error is reported
/// (from the mmap, when both meta reads fail).
fn select_meta(data: &[u8]) -> Result<MetaInfo, MetaError> {
    let meta0 = parse_meta_page(data);
    let meta1 = match &meta0 {
        Ok(meta) => data.get(meta.page_size..).map_or(Err(MetaError::Invalid), parse_meta_page),
        Err(_) => find_meta1_at_unknown_page_size(data),
    };

    match (meta0, meta1) {
        (Err(err), Err(_)) => Err(err),
        (Ok(meta), Err(_)) | (Err(_), Ok(meta)) => Ok(meta),
        (Ok(meta0), Ok(meta1)) => Ok(if meta1.txid > meta0.txid { meta1 } else { meta0 }),
    }
}

/// When meta page 0 fails validation the true page size is
/// unknown, so meta page 1's offset is unknown too — scan every size the format itself considers
/// (`1024 << i` for `i` in `0..=14`, i.e. 1 KiB up to 16 MiB) until one offset parses as a valid
/// meta page.
fn find_meta1_at_unknown_page_size(data: &[u8]) -> Result<MetaInfo, MetaError> {
    (0..=14u32)
        .map(|i| 1024usize << i)
        .find_map(|offset| data.get(offset..).and_then(|tail| parse_meta_page(tail).ok()))
        .ok_or(MetaError::Invalid)
}

fn read_page_header(data: &[u8], page_size: usize, id: u64) -> Result<(u16, u16, u32), Error> {
    let start = page_offset(page_size, id).ok_or(Error::Invalid)?;
    let flags = read_u16(data, start + 8).ok_or(Error::Invalid)?;
    let count = read_u16(data, start + 10).ok_or(Error::Invalid)?;
    let overflow = read_u32(data, start + 12).ok_or(Error::Invalid)?;
    Ok((flags, count, overflow))
}

fn page_span(data: &[u8], page_size: usize, id: u64, overflow: u32) -> Result<&[u8], Error> {
    let start = page_offset(page_size, id).ok_or(Error::Invalid)?;
    let len = page_size.checked_mul(1 + overflow as usize).ok_or(Error::Invalid)?;
    data.get(start..start.checked_add(len).ok_or(Error::Invalid)?).ok_or(Error::Invalid)
}

/// A page in `0..FREELIST_PAGE_ID` is one of the two meta pages, never real content; a span
/// reaching `meta_pgid` (the selected meta's own high-water mark) overlaps ids a commit is free to
/// reuse. Either makes a reachable id untrustworthy, so `decode` rejects the whole file instead of
/// folding it into `live`.
fn check_reachable_span(id: u64, overflow: u32, meta_pgid: u64) -> Result<(), Error> {
    if id < FREELIST_PAGE_ID {
        return Err(Error::Invalid);
    }
    let end = id.checked_add(u64::from(overflow)).ok_or(Error::Invalid)?;
    if end >= meta_pgid {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn collect_leaf_entries(
    data: &[u8],
    page_size: usize,
    page: &[u8],
    depth: u32,
    meta_pgid: u64,
    out: &mut Vec<(Vec<u8>, u32, Vec<u8>)>,
    live: &mut Vec<u64>,
) -> Result<(), Error> {
    if depth > MAX_TREE_DEPTH {
        return Err(Error::Invalid);
    }
    let header = page.get(0..PAGE_HEADER_SIZE).ok_or(Error::Invalid)?;
    let flags = read_u16(header, 8).ok_or(Error::Invalid)?;
    let count = usize::from(read_u16(header, 10).ok_or(Error::Invalid)?);

    if flags == PAGE_FLAG_LEAF {
        for i in 0..count {
            let elem_off = PAGE_HEADER_SIZE + i * LEAF_ELEM_SIZE;
            let elem = page.get(elem_off..elem_off + LEAF_ELEM_SIZE).ok_or(Error::Invalid)?;
            let elem_flags = read_u32(elem, 0).ok_or(Error::Invalid)?;
            let pos = read_u32(elem, 4).ok_or(Error::Invalid)? as usize;
            let ksize = read_u32(elem, 8).ok_or(Error::Invalid)? as usize;
            let vsize = read_u32(elem, 12).ok_or(Error::Invalid)? as usize;
            let key_start = elem_off.checked_add(pos).ok_or(Error::Invalid)?;
            let key_end = key_start.checked_add(ksize).ok_or(Error::Invalid)?;
            let val_end = key_end.checked_add(vsize).ok_or(Error::Invalid)?;
            let key = page.get(key_start..key_end).ok_or(Error::Invalid)?.to_vec();
            let value = page.get(key_end..val_end).ok_or(Error::Invalid)?.to_vec();
            out.push((key, elem_flags, value));
        }
        Ok(())
    } else if flags == PAGE_FLAG_BRANCH {
        for i in 0..count {
            let elem_off = PAGE_HEADER_SIZE + i * BRANCH_ELEM_SIZE;
            let elem = page.get(elem_off..elem_off + BRANCH_ELEM_SIZE).ok_or(Error::Invalid)?;
            let pgid = read_u64(elem, 8).ok_or(Error::Invalid)?;
            let (_, _, child_overflow) = read_page_header(data, page_size, pgid)?;
            check_reachable_span(pgid, child_overflow, meta_pgid)?;
            let child = page_span(data, page_size, pgid, child_overflow)?;
            live.extend(pgid..=pgid + u64::from(child_overflow));
            collect_leaf_entries(data, page_size, child, depth + 1, meta_pgid, out, live)?;
        }
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

fn read_bucket(
    data: &[u8],
    page_size: usize,
    root_pgid: u64,
    inline_page: Option<&[u8]>,
    depth: u32,
    meta_pgid: u64,
    live: &mut Vec<u64>,
) -> Result<BTreeMap<Vec<u8>, Entry>, Error> {
    if depth > MAX_TREE_DEPTH {
        return Err(Error::Invalid);
    }
    let mut flat = Vec::new();
    if root_pgid == 0 {
        collect_leaf_entries(data, page_size, inline_page.ok_or(Error::Invalid)?, depth, meta_pgid, &mut flat, live)?;
    } else {
        let (_, _, overflow) = read_page_header(data, page_size, root_pgid)?;
        check_reachable_span(root_pgid, overflow, meta_pgid)?;
        let page = page_span(data, page_size, root_pgid, overflow)?;
        live.extend(root_pgid..=root_pgid + u64::from(overflow));
        collect_leaf_entries(data, page_size, page, depth, meta_pgid, &mut flat, live)?;
    }

    let mut map = BTreeMap::new();
    for (key, flags, value) in flat {
        if flags & BUCKET_LEAF_FLAG != 0 {
            if value.len() < BUCKET_HEADER_SIZE {
                return Err(Error::Invalid);
            }
            let child_root = read_u64(&value, 0).ok_or(Error::Invalid)?;
            let child = if child_root == 0 {
                let inline = value.get(BUCKET_HEADER_SIZE..).ok_or(Error::Invalid)?;
                read_bucket(data, page_size, 0, Some(inline), depth + 1, meta_pgid, live)?
            } else {
                read_bucket(data, page_size, child_root, None, depth + 1, meta_pgid, live)?
            };
            map.insert(key, Entry::Bucket(child));
        } else {
            map.insert(key, Entry::Value(value));
        }
    }
    Ok(map)
}

/// A traversal of the selected meta's tree and freelist: `decode` needs the
/// full set of pages that meta can reach so `Db::open` can tell live pages from ones a torn or
/// stale generation left behind (see the module doc). Returns the reachable page ids alongside the
/// decoded buckets.
fn decode(data: &[u8]) -> Result<(Buckets, usize, u64, u64, Vec<u64>), Error> {
    let meta = select_meta(data)?;
    let mut live = Vec::new();
    let tree = read_bucket(data, meta.page_size, meta.root_pgid, None, 0, meta.pgid, &mut live)?;

    if meta.freelist != 0 {
        let (_, _, freelist_overflow) = read_page_header(data, meta.page_size, meta.freelist)?;
        page_span(data, meta.page_size, meta.freelist, freelist_overflow)?;
        check_reachable_span(meta.freelist, freelist_overflow, meta.pgid)?;
        live.extend(meta.freelist..=meta.freelist + u64::from(freelist_overflow));
    }

    let mut buckets = Buckets::new();
    for (name, entry) in tree {
        let Entry::Bucket(inner) = entry else { return Err(Error::Invalid) };
        let mut kv = BTreeMap::new();
        for (key, entry) in inner {
            let Entry::Value(value) = entry else { return Err(Error::Invalid) };
            kv.insert(key, value);
        }
        buckets.insert(name, kv);
    }
    live.sort_unstable();
    live.dedup();
    Ok((buckets, meta.page_size, meta.txid, meta.pgid, live))
}

#[cfg(test)]
mod tests {
    use super::{
        chunk_ranges, decode, encode, encode_tree, fnv64a, read_bucket, write_bucket, Buckets, Db, Entry, Error,
        Options, PageWriter, BUCKET_LEAF_FLAG, META_CHECKSUM_OFFSET, PAGE_FLAG_BRANCH, PAGE_FLAG_FREELIST,
        PAGE_FLAG_LEAF, PAGE_FLAG_META, PAGE_HEADER_SIZE,
    };
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    #[test]
    fn fnv64a_matches_hash_fnv_new64a() {
        // "" -> offset basis; "a" from the FNV-1a reference test vectors.
        assert_eq!(fnv64a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv64a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn chunk_ranges_closes_a_run_only_after_the_min_keys_per_page_floor() {
        assert_eq!(chunk_ranges(64, &[]), vec![(0, 0)]);
        assert_eq!(chunk_ranges(64, &[10]), vec![(0, 1)]);
        assert_eq!(chunk_ranges(32, &[10, 10, 10]), vec![(0, 2), (2, 3)]);
        assert_eq!(chunk_ranges(16, &[100, 5]), vec![(0, 2)]);
        // Every entry alone already overflows the page; the floor still pairs them up instead
        // of producing one range per entry, which is what keeps `write_branch_level`'s
        // recursion over the resulting level shrinking instead of looping forever.
        assert_eq!(chunk_ranges(16, &[100, 100, 100, 100, 100]), vec![(0, 2), (2, 4), (4, 5)]);
    }

    fn roundtrip_buckets(buckets: &Buckets, page_size: usize) -> Buckets {
        let bytes = encode(buckets, page_size, 7);
        let (decoded, decoded_page_size, decoded_txid, _pgid, _live) =
            decode(&bytes).expect("decode written bbolt file");
        assert_eq!(decoded_page_size, page_size);
        assert_eq!(decoded_txid, 7);
        decoded
    }

    #[test]
    fn roundtrip_empty_and_populated_buckets() {
        let mut buckets = Buckets::new();
        buckets.insert(b"empty".to_vec(), BTreeMap::new());
        let mut selected = BTreeMap::new();
        selected.insert(b"Proxy".to_vec(), b"ProxyA".to_vec());
        buckets.insert(b"selected".to_vec(), selected);

        assert_eq!(roundtrip_buckets(&buckets, 4096), buckets);
    }

    #[test]
    fn roundtrip_many_keys_forces_branch_pages() {
        let mut kv = BTreeMap::new();
        for i in 0..2000u32 {
            kv.insert(format!("key-{i:06}").into_bytes(), vec![b'v'; 32]);
        }
        let mut buckets = Buckets::new();
        buckets.insert(b"bucket".to_vec(), kv.clone());

        let bytes = encode(&buckets, 512, 1);
        let meta = super::select_meta(&bytes).expect("valid meta");

        let mut root_entries = Vec::new();
        let (_, _, root_overflow) =
            super::read_page_header(&bytes, meta.page_size, meta.root_pgid).expect("root page header");
        let root_page =
            super::page_span(&bytes, meta.page_size, meta.root_pgid, root_overflow).expect("root page span");
        super::collect_leaf_entries(
            &bytes,
            meta.page_size,
            root_page,
            0,
            meta.pgid,
            &mut root_entries,
            &mut Vec::new(),
        )
        .expect("read root bucket's own leaf entries");
        let (_, _, bucket_value) =
            root_entries.into_iter().find(|(key, _, _)| key == b"bucket").expect("bucket entry in db root");
        let bucket_root_pgid = u64::from_le_bytes(bucket_value[0..8].try_into().unwrap());

        let (bucket_flags, _, _) =
            super::read_page_header(&bytes, meta.page_size, bucket_root_pgid).expect("bucket root page header");
        assert_eq!(
            bucket_flags, PAGE_FLAG_BRANCH,
            "2000 32-byte values in 512-byte pages must not fit in a single leaf page"
        );

        let decoded = roundtrip_buckets(&buckets, 512);
        assert_eq!(decoded, buckets);
    }

    #[test]
    fn decode_rejects_a_branch_child_at_or_past_meta_pgid() {
        let mut kv = BTreeMap::new();
        for i in 0..2000u32 {
            kv.insert(format!("key-{i:06}").into_bytes(), vec![b'v'; 32]);
        }
        let mut buckets = Buckets::new();
        buckets.insert(b"bucket".to_vec(), kv);

        let mut bytes = encode(&buckets, 512, 1);
        bytes.extend(vec![0u8; 512 * 8]);
        let meta = super::select_meta(&bytes).expect("valid meta");

        let mut root_entries = Vec::new();
        let (_, _, root_overflow) =
            super::read_page_header(&bytes, meta.page_size, meta.root_pgid).expect("root page header");
        let root_page =
            super::page_span(&bytes, meta.page_size, meta.root_pgid, root_overflow).expect("root page span").to_vec();
        super::collect_leaf_entries(
            &bytes,
            meta.page_size,
            &root_page,
            0,
            meta.pgid,
            &mut root_entries,
            &mut Vec::new(),
        )
        .expect("read root bucket's own leaf entries");
        let (_, _, bucket_value) =
            root_entries.into_iter().find(|(key, _, _)| key == b"bucket").expect("bucket entry in db root");
        let bucket_root_pgid = u64::from_le_bytes(bucket_value[0..8].try_into().unwrap());
        let (bucket_flags, _, _) =
            super::read_page_header(&bytes, meta.page_size, bucket_root_pgid).expect("bucket root page header");
        assert_eq!(bucket_flags, PAGE_FLAG_BRANCH, "fixture must force a branch page to corrupt a child pointer");

        let elem_off = bucket_root_pgid as usize * meta.page_size + PAGE_HEADER_SIZE + 8;
        let old_child = u64::from_le_bytes(bytes[elem_off..elem_off + 8].try_into().unwrap());
        let src = old_child as usize * meta.page_size;
        let dst = meta.pgid as usize * meta.page_size;
        bytes.copy_within(src..src + meta.page_size, dst);
        bytes[elem_off..elem_off + 8].copy_from_slice(&meta.pgid.to_le_bytes());

        let err = decode(&bytes).expect_err("a branch child at the high-water mark must be rejected");
        assert!(matches!(err, Error::Invalid), "expected Error::Invalid, got {err:?}");
    }

    #[test]
    fn decode_rejects_a_corrupt_freelist_span() {
        let mut buckets = Buckets::new();
        let mut selected = BTreeMap::new();
        selected.insert(b"Proxy".to_vec(), b"ProxyA".to_vec());
        buckets.insert(b"selected".to_vec(), selected);
        let page_size = 4096;

        // A corrupt overflow count must not make `decode` reserve gigabytes before it notices the
        // span cannot fit in the file.
        let mut huge_overflow = encode(&buckets, page_size, 7);
        let meta = super::select_meta(&huge_overflow).expect("valid meta");
        let overflow_off = meta.freelist as usize * page_size + 12;
        huge_overflow[overflow_off..overflow_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let err = decode(&huge_overflow).expect_err("a corrupt freelist overflow count must be rejected");
        assert!(matches!(err, Error::Invalid), "expected Error::Invalid, got {err:?}");

        // A freelist field pointing at meta page 1 must not become live and then free.
        let mut on_meta_page = encode(&buckets, page_size, 7);
        let meta = super::select_meta(&on_meta_page).expect("valid meta");
        super::write_meta(
            &mut on_meta_page[0..page_size],
            page_size as u32,
            meta.root_pgid,
            0,
            1,
            meta.pgid,
            meta.txid,
        );
        let err = decode(&on_meta_page).expect_err("a freelist pointing at a meta page must be rejected");
        assert!(matches!(err, Error::Invalid), "expected Error::Invalid, got {err:?}");
    }

    #[test]
    fn write_branch_level_terminates_for_keys_larger_than_half_a_page() {
        let page_size = 4096usize;
        let mut kv = BTreeMap::new();
        for i in 0..40u32 {
            let mut key = vec![b'k'; 4000];
            let label = format!("bk-{i:04}");
            key[..label.len()].copy_from_slice(label.as_bytes());
            kv.insert(key, b"x".to_vec());
        }
        let mut buckets = Buckets::new();
        buckets.insert(b"bigkeys".to_vec(), kv);

        assert_eq!(roundtrip_buckets(&buckets, page_size), buckets);
    }

    /// Fixture in the bolt file format.
    #[test]
    fn rust_commits_on_the_bigkey_fixture() {
        let fixture = include_bytes!("testdata/cache_bigkeys.db");
        let dir = std::env::temp_dir().join(format!("bolt-bigkeys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");
        std::fs::write(&path, fixture).unwrap();

        let db = Db::open(path.to_str().unwrap(), 0o600, &Options::default()).expect("open the 4000-byte-key fixture");
        db.batch(|tx| {
            let mut b = tx.create_bucket_if_not_exists(b"bigkeys")?;
            b.put(b"rust-added", b"y")?;
            Ok(())
        })
        .expect("commit on a file with 4000-byte keys must not recurse forever");

        let mut file = std::fs::File::open(&path).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();
        let (buckets, ..) = decode(&data).expect("file stays decodable after the commit");
        let bigkeys = buckets.get(b"bigkeys".as_slice()).expect("bigkeys bucket survives");
        assert_eq!(bigkeys.get(b"rust-added".as_slice()), Some(&b"y".to_vec()));
        let mut preserved_key = vec![0u8; 4000];
        preserved_key[..b"bk-0000".len()].copy_from_slice(b"bk-0000");
        assert_eq!(
            bigkeys.get(&preserved_key),
            Some(&b"x".to_vec()),
            "a 4000-byte key from the fixture survives the commit"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn roundtrip_nested_bucket_and_overflow_value() {
        let mut child = BTreeMap::new();
        child.insert(b"leaf-key".to_vec(), Entry::Value(vec![b'x'; 6000]));
        let mut root = BTreeMap::new();
        root.insert(b"parent".to_vec(), Entry::Bucket(child.clone()));
        root.insert(b"sibling".to_vec(), Entry::Value(b"plain".to_vec()));

        let bytes = encode_tree(&root, 4096, 3);
        let meta = super::select_meta(&bytes).expect("valid meta");
        let decoded = read_bucket(&bytes, meta.page_size, meta.root_pgid, None, 0, meta.pgid, &mut Vec::new())
            .expect("read nested tree");

        assert_eq!(decoded, root);
        let Entry::Bucket(decoded_child) = &decoded[&b"parent".to_vec()] else { panic!("expected bucket") };
        assert_eq!(decoded_child, &child);
    }

    /// Fixture in the bolt file format.
    #[test]
    fn open_reads_the_cache_fixture() {
        let fixture = include_bytes!("testdata/cache_fixture.db");
        let dir = std::env::temp_dir().join(format!("bolt-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");
        std::fs::write(&path, fixture).unwrap();

        let db = Db::open(path.to_str().unwrap(), 0o600, &Options::default()).expect("open the cache fixture");
        let mut selected = None;
        let mut host_ip = None;
        let mut etag = None;
        db.view(|tx| {
            if let Some(bucket) = tx.bucket(b"selected") {
                selected = bucket.get(b"Proxy").map(<[u8]>::to_vec);
            }
            if let Some(bucket) = tx.bucket(b"fakeip") {
                host_ip = bucket.get(b"example.com").map(<[u8]>::to_vec);
            }
            if let Some(bucket) = tx.bucket(b"etag") {
                etag = bucket.get(b"https://example.com/config.yaml").map(<[u8]>::to_vec);
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(selected.as_deref(), Some(b"ProxyA".as_slice()));
        assert_eq!(host_ip.as_deref(), Some([198, 18, 0, 1].as_slice()));
        assert!(etag.is_some(), "etag entry should be present");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_creates_a_fresh_file_with_a_valid_meta_page() {
        let dir = std::env::temp_dir().join(format!("bolt-fresh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");

        let db = Db::open(path.to_str().unwrap(), 0o600, &Options::default()).expect("create fresh cache.db");
        db.batch(|tx| {
            let mut bucket = tx.create_bucket_if_not_exists(b"selected")?;
            bucket.put(b"Proxy", b"ProxyB")?;
            Ok(())
        })
        .unwrap();

        let mut file = std::fs::File::open(&path).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();
        let meta = super::select_meta(&data).expect("freshly written file has a valid meta page");
        assert_eq!(meta.page_size, super::DEFAULT_PAGE_SIZE);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn select_meta_recovers_page_size_from_meta1_when_meta0_is_corrupted() {
        let mut selected = BTreeMap::new();
        selected.insert(b"Proxy".to_vec(), b"ProxyA".to_vec());
        let mut buckets = Buckets::new();
        buckets.insert(b"selected".to_vec(), selected);

        let mut bytes = encode(&buckets, 16384, 5);
        bytes[PAGE_HEADER_SIZE + META_CHECKSUM_OFFSET] ^= 0xFF;

        let meta = super::select_meta(&bytes).expect("recovers via meta page 1 at the true page size");
        assert_eq!(meta.page_size, 16384);

        let decoded = read_bucket(&bytes, meta.page_size, meta.root_pgid, None, 0, meta.pgid, &mut Vec::new())
            .expect("read root bucket");
        let Entry::Bucket(sel) = &decoded[&b"selected".to_vec()] else { panic!("expected bucket") };
        assert_eq!(sel[&b"Proxy".to_vec()], Entry::Value(b"ProxyA".to_vec()));
    }

    #[test]
    fn page_flag_constants_match_the_on_disk_format() {
        assert_eq!(PAGE_FLAG_BRANCH, 0x01);
        assert_eq!(PAGE_FLAG_LEAF, 0x02);
        assert_eq!(PAGE_FLAG_META, 0x04);
        assert_eq!(PAGE_FLAG_FREELIST, 0x10);
        assert_eq!(BUCKET_LEAF_FLAG, 0x01);
    }

    /// Fixture in the bolt file format.
    #[test]
    fn open_reads_the_branch_and_overflow_fixture() {
        let fixture = include_bytes!("testdata/cache_branch_overflow.db");

        let meta = super::select_meta(fixture).expect("valid meta in the fixture");
        let (_, _, root_overflow) =
            super::read_page_header(fixture, meta.page_size, meta.root_pgid).expect("root page header");
        let root_page =
            super::page_span(fixture, meta.page_size, meta.root_pgid, root_overflow).expect("root page span");
        let mut root_entries = Vec::new();
        super::collect_leaf_entries(
            fixture,
            meta.page_size,
            root_page,
            0,
            meta.pgid,
            &mut root_entries,
            &mut Vec::new(),
        )
        .expect("read db root bucket entries");
        let (_, _, selected_value) =
            root_entries.iter().find(|(key, _, _)| key == b"selected").expect("selected bucket in db root");
        let selected_root = u64::from_le_bytes(selected_value[0..8].try_into().unwrap());
        let (selected_flags, _, _) =
            super::read_page_header(fixture, meta.page_size, selected_root).expect("selected bucket root header");
        assert_eq!(selected_flags, PAGE_FLAG_BRANCH, "3000 keys must not fit on a single leaf page");

        let dir = std::env::temp_dir().join(format!("bolt-branch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");
        std::fs::write(&path, fixture).unwrap();

        let db = Db::open(path.to_str().unwrap(), 0o600, &Options::default()).expect("open branch/overflow fixture");
        let mut selected_count = 0usize;
        let mut storage_len = None;
        db.view(|tx| {
            if let Some(bucket) = tx.bucket(b"selected") {
                let mut cursor = bucket.cursor();
                let mut entry = cursor.first();
                while entry.is_some() {
                    selected_count += 1;
                    entry = cursor.next();
                }
            }
            if let Some(bucket) = tx.bucket(b"storage") {
                storage_len = bucket.get(b"big").map(<[u8]>::len);
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(selected_count, 3001, "3000 generated groups plus the original \"Proxy\" selection");
        assert!(
            storage_len.is_some_and(|len| len > 200 * 1024),
            "msgpack-wrapped 200 KB storage value must round-trip through overflow pages, got {storage_len:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reopening_between_commits_does_not_grow_the_file_without_bound() {
        let dir = std::env::temp_dir().join(format!("bolt-reopen-growth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");
        let path = path.to_str().unwrap();
        let options = Options { timeout: Some(Duration::from_secs(1)), ..Options::default() };

        let db = Db::open(path, 0o600, &options).expect("initial open");
        db.batch(|tx| {
            let mut bucket = tx.create_bucket_if_not_exists(b"selected")?;
            for i in 0..500 {
                bucket.put(format!("group-{i:06}").as_bytes(), format!("value-{i:06}").as_bytes())?;
            }
            Ok(())
        })
        .unwrap();
        drop(db);

        let mut sizes = Vec::new();
        for round in 0..8 {
            let db = Db::open(path, 0o600, &options).expect("reopen");
            db.batch(|tx| {
                let mut bucket = tx.create_bucket_if_not_exists(b"selected")?;
                bucket.put(b"group-000000", format!("round-{round}").as_bytes())?;
                Ok(())
            })
            .unwrap();
            drop(db);
            sizes.push(std::fs::metadata(path).unwrap().len());
        }

        let plateau = *sizes.last().unwrap();
        assert!(
            sizes[3..].iter().all(|&s| s == plateau),
            "reopening between commits must reuse the on-disk freelist and plateau, not append a full tree \
             per reopen: sizes across rounds {sizes:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_blocks_a_second_open_until_the_first_is_dropped() {
        let dir = std::env::temp_dir().join(format!("bolt-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");
        let options = Options { timeout: Some(Duration::from_secs(1)), ..Options::default() };

        let first = Db::open(path.to_str().unwrap(), 0o600, &options).expect("first open acquires the lock");

        let start = Instant::now();
        let second = Db::open(path.to_str().unwrap(), 0o600, &options);
        let elapsed = start.elapsed();
        assert!(matches!(second, Err(Error::Timeout)), "second open should time out while the first is alive");
        assert!(elapsed >= Duration::from_millis(900), "should wait close to the full timeout, took {elapsed:?}");

        drop(first);
        Db::open(path.to_str().unwrap(), 0o600, &options).expect("open succeeds once the first is dropped");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bucket_leaf_flag_marks_nested_bucket_entries() {
        let mut writer = PageWriter::new(4096, 3, Vec::new());
        let mut inner = BTreeMap::new();
        inner.insert(b"k".to_vec(), Entry::Value(b"v".to_vec()));
        let mut root = BTreeMap::new();
        root.insert(b"bucket".to_vec(), Entry::Bucket(inner));
        let root_pgid = write_bucket(&mut writer, &root);

        let (_, leaf) = writer.regions.iter().find(|(id, _)| *id == root_pgid).expect("root page region");
        let flags = u32::from_le_bytes(leaf[16..20].try_into().unwrap());
        assert_eq!(flags & BUCKET_LEAF_FLAG, BUCKET_LEAF_FLAG);
    }

    #[test]
    fn commits_write_new_pages_in_place_and_alternate_the_meta_page() {
        let dir = std::env::temp_dir().join(format!("bolt-inplace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");

        let db = Db::open(path.to_str().unwrap(), 0o600, &Options::default()).unwrap();
        db.batch(|tx| {
            let mut bucket = tx.create_bucket_if_not_exists(b"selected")?;
            bucket.put(b"Proxy", b"A")?;
            Ok(())
        })
        .unwrap();
        let after_first = std::fs::read(&path).unwrap();
        let meta_after_first = super::select_meta(&after_first).unwrap();
        assert_eq!(meta_after_first.txid, 2, "open's fresh init is txid 1, the first batch commits txid 2");

        db.batch(|tx| {
            let mut bucket = tx.bucket(b"selected").expect("bucket created above");
            bucket.put(b"Proxy", b"B")?;
            Ok(())
        })
        .unwrap();
        let after_second = std::fs::read(&path).unwrap();
        assert!(after_second.len() >= after_first.len(), "in-place commits never truncate the file");

        let page_size = meta_after_first.page_size;
        let meta0 = super::parse_meta_page(&after_second[..page_size]).unwrap();
        let meta1 = super::parse_meta_page(&after_second[page_size..2 * page_size]).unwrap();
        assert_ne!(meta0.txid, meta1.txid, "each commit only overwrites the meta page at txid % 2");
        assert_eq!(meta0.txid.max(meta1.txid), 3);

        let mut selected = None;
        db.view(|tx| {
            selected = tx.bucket(b"selected").and_then(|b| b.get(b"Proxy").map(<[u8]>::to_vec));
            Ok(())
        })
        .unwrap();
        assert_eq!(selected.as_deref(), Some(b"B".as_slice()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_crash_between_the_content_write_and_the_meta_write_leaves_the_previous_state() {
        let dir = std::env::temp_dir().join(format!("bolt-crash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");

        let db = Db::open(path.to_str().unwrap(), 0o600, &Options::default()).unwrap();
        db.batch(|tx| {
            let mut bucket = tx.create_bucket_if_not_exists(b"selected")?;
            bucket.put(b"Proxy", b"A")?;
            Ok(())
        })
        .unwrap();
        let valid_state = std::fs::read(&path).unwrap();
        drop(db);

        // A crash that reached `commit_in_place`'s first fsync (new content pages written and
        // durable) but never its meta write leaves bytes past the old high-water mark that no
        // on-disk meta references — exactly what appending here simulates.
        {
            let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[0xAA; 4096]).unwrap();
        }

        let reopened = Db::open(path.to_str().unwrap(), 0o600, &Options::default()).expect("reopen after a torn write");
        let mut selected = None;
        reopened
            .view(|tx| {
                selected = tx.bucket(b"selected").and_then(|b| b.get(b"Proxy").map(<[u8]>::to_vec));
                Ok(())
            })
            .unwrap();
        assert_eq!(selected.as_deref(), Some(b"A".as_slice()), "the crash left the previous valid commit intact");

        let after_reopen = std::fs::read(&path).unwrap();
        assert_eq!(
            &after_reopen[..valid_state.len()],
            &valid_state[..],
            "the previous generation's bytes are untouched"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repeated_updates_to_the_same_keys_keep_the_file_bounded() {
        let dir = std::env::temp_dir().join(format!("bolt-bounded-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");

        let db = Db::open(path.to_str().unwrap(), 0o600, &Options::default()).unwrap();
        db.batch(|tx| {
            let mut bucket = tx.create_bucket_if_not_exists(b"selected")?;
            for i in 0..200u32 {
                bucket.put(format!("group-{i:04}").as_bytes(), b"DIRECT")?;
            }
            Ok(())
        })
        .unwrap();

        let mut sizes = Vec::new();
        for i in 0..60u32 {
            db.batch(|tx| {
                let mut bucket = tx.bucket(b"selected").expect("preloaded above");
                bucket.put(format!("group-{:04}", i % 200).as_bytes(), b"REJECT")?;
                Ok(())
            })
            .unwrap();
            sizes.push(std::fs::metadata(&path).unwrap().len());
        }

        let warm = sizes[9];
        let last = *sizes.last().unwrap();
        assert!(
            last <= warm * 2,
            "reviewer's workload 1 at a smaller N: growth must plateau once pages have cycled \
             through reuse, not keep compounding: sizes={sizes:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn distinct_new_keys_grow_roughly_linearly_not_exponentially() {
        let dir = std::env::temp_dir().join(format!("bolt-linear-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");

        let db = Db::open(path.to_str().unwrap(), 0o600, &Options::default()).unwrap();
        let mut sizes = Vec::new();
        for i in 0..80u32 {
            db.batch(|tx| {
                let mut bucket = tx.create_bucket_if_not_exists(b"fakeip")?;
                bucket.put(format!("host-{i:05}.example").as_bytes(), &i.to_le_bytes())?;
                Ok(())
            })
            .unwrap();
            sizes.push(std::fs::metadata(&path).unwrap().len());
        }

        let at_40 = sizes[39];
        let at_80 = sizes[79];
        assert!(
            at_80 <= at_40 * 3,
            "reviewer's workload 2 at a smaller N: doubling the key count must not roughly square \
             the file, only grow with the data: at_40={at_40} at_80={at_80} sizes={sizes:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn torn_writes_that_reuse_pages_still_recover_the_previous_state() {
        let dir = std::env::temp_dir().join(format!("bolt-torn-reuse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.db");

        let db = Db::open(path.to_str().unwrap(), 0o600, &Options::default()).unwrap();
        for i in 0..3u32 {
            db.batch(|tx| {
                let mut bucket = tx.create_bucket_if_not_exists(b"selected")?;
                bucket.put(format!("Proxy{i}").as_bytes(), b"A")?;
                Ok(())
            })
            .unwrap();
        }
        let valid_state = std::fs::read(&path).unwrap();

        db.batch(|tx| {
            let mut bucket = tx.bucket(b"selected").expect("created above");
            bucket.put(b"Proxy3", b"B")?;
            Ok(())
        })
        .unwrap();
        let final_state = std::fs::read(&path).unwrap();
        drop(db);

        let page_size = super::select_meta(&valid_state).unwrap().page_size;
        let overlap = valid_state.len().min(final_state.len());
        let non_meta_changed: Vec<usize> =
            (2 * page_size..overlap).filter(|&i| valid_state[i] != final_state[i]).collect();
        assert!(
            !non_meta_changed.is_empty(),
            "this commit must overwrite at least one reused content page below the old high-water mark"
        );

        // Content is fully durable in every case (the commit's first fsync succeeded); only how
        // much of it actually landed on disk varies, and every cut here stops before the meta
        // write, so recovery must always land back on the untouched previous meta.
        for &cut in &[0, non_meta_changed.len() / 3, non_meta_changed.len() * 2 / 3, non_meta_changed.len()] {
            let mut candidate = valid_state.clone();
            candidate.resize(final_state.len(), 0);
            candidate[overlap..].copy_from_slice(&final_state[overlap..]);
            for &pos in &non_meta_changed[..cut] {
                candidate[pos] = final_state[pos];
            }

            std::fs::write(&path, &candidate).unwrap();
            let reopened = Db::open(path.to_str().unwrap(), 0o600, &Options::default())
                .unwrap_or_else(|err| panic!("reopen a torn content write (cut={cut}) must succeed: {err}"));
            let mut has_new_key = None;
            reopened
                .view(|tx| {
                    has_new_key = tx.bucket(b"selected").and_then(|b| b.get(b"Proxy3").map(<[u8]>::to_vec));
                    Ok(())
                })
                .unwrap();
            assert!(has_new_key.is_none(), "cut={cut}: a torn content write must never surface the new commit");
            drop(reopened);
        }

        // Torn meta write: content is fully durable but the alternate meta's own fsync only
        // partly landed — that must fail its checksum and fall back to the other, still valid,
        // untouched meta slot.
        let valid_txid = super::select_meta(&valid_state).unwrap().txid;
        let meta_slot = ((valid_txid + 1) % 2) as usize;
        let meta_span = PAGE_HEADER_SIZE + super::META_SIZE;
        for meta_cut in (0..meta_span).step_by(8) {
            let mut candidate = final_state.clone();
            let start = meta_slot * page_size;
            candidate[start + meta_cut..start + page_size].fill(0);

            std::fs::write(&path, &candidate).unwrap();
            let reopened = Db::open(path.to_str().unwrap(), 0o600, &Options::default())
                .unwrap_or_else(|err| panic!("reopen a torn meta write (meta_cut={meta_cut}) must succeed: {err}"));
            let mut selected = None;
            reopened
                .view(|tx| {
                    selected = tx.bucket(b"selected").and_then(|b| b.get(b"Proxy3").map(<[u8]>::to_vec));
                    Ok(())
                })
                .unwrap();
            assert!(
                selected.is_none(),
                "meta_cut={meta_cut}: a torn meta write must fall back to the previous valid meta"
            );
            drop(reopened);
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}
