//! A handle decodes its entry up front, so the archive is the only resource `close` releases; the
//! handle owns the archive reader so its lifetime spans the entry's.

use std::io::{self, Cursor, Read};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use sevenz_rust2::{ArchiveReader, Password};

use murmur_component_resource::fetcher::{BundleFile, BundleFileHandle};
use murmur_constant::path::PATH;

#[must_use]
pub fn make_bundle_file(path: &str) -> Option<BundleFile> {
    if path.is_empty() {
        return None;
    }
    let path = path.to_owned();
    Some(Arc::new(move || open(&path)))
}

pub fn open(path: &str) -> Result<Box<dyn BundleFileHandle>> {
    let mut archive = ArchiveReader::open(PATH.bundle_mrs(), Password::empty())
        .map_err(|err| anyhow!("open bundle file error: {err}"))?;
    let data = archive.read_file(path).map_err(|err| anyhow!("open path in bundle file error: {err}"))?;
    let mod_time = archive
        .archive()
        .files
        .iter()
        .find(|entry| entry.name() == path)
        .map_or_else(Utc::now, |entry| DateTime::<Utc>::from(SystemTime::from(entry.last_modified_date())));
    Ok(Box::new(File { data: Cursor::new(data), mod_time, archive: Some(archive) }))
}

pub(crate) struct File {
    data: Cursor<Vec<u8>>,
    mod_time: DateTime<Utc>,
    archive: Option<ArchiveReader<std::fs::File>>,
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.data.read(buf)
    }
}

impl BundleFileHandle for File {
    fn mod_time(&self) -> Result<DateTime<Utc>> {
        Ok(self.mod_time)
    }

    /// Only the archive holds a resource here, so a second close is a no-op.
    fn close(&mut self) -> Result<()> {
        self.archive = None;
        Ok(())
    }
}
