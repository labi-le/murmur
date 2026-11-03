use murmur_quic::congestion::PacketNumber;

use super::bbr_sender::INVALID_PACKET_NUMBER;
use super::ringbuffer::RingBuffer;

/// packetNumberIndexedQueue is a queue of mostly continuous numbered entries
/// which supports the following operations:
/// - adding elements to the end of the queue, or at some point past the end
/// - removing elements in any order
/// - retrieving elements
///
/// If all elements are inserted in order, all of the operations above are
/// amortized O(1) time.
///
/// Internally, the data structure is a deque where each element is marked as
/// present or not.  The deque starts at the lowest present index.  Whenever an
/// element is removed, it's marked as not present, and the front of the deque is
/// cleared of elements that are not present.
///
/// The tail of the queue is not cleared due to the assumption of entries being
/// inserted in order, though removing all elements of the queue will return it
/// to its initial state.
///
/// Note that this data structure is inherently hazardous, since an addition of
/// just two entries will cause it to consume all of the memory available.
/// Because of that, it is not a general-purpose container and should not be used
/// as one.
#[derive(Debug)]
pub(crate) struct PacketNumberIndexedQueue<T> {
    entries: RingBuffer<EntryWrapper<T>>,
    number_of_present_entries: usize,
    first_packet: PacketNumber,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EntryWrapper<T> {
    pub(crate) present: bool,
    pub(crate) entry: T,
}

pub(crate) fn new_packet_number_indexed_queue<T: Clone + Default>(size: usize) -> PacketNumberIndexedQueue<T> {
    let mut q = PacketNumberIndexedQueue {
        entries: RingBuffer::default(),
        number_of_present_entries: 0,
        first_packet: INVALID_PACKET_NUMBER,
    };

    q.entries.init(size);

    q
}

impl<T: Clone + Default> PacketNumberIndexedQueue<T> {
    /// Emplace inserts data associated |`packet_number`| into (or past) the end of
    /// the queue, filling up the missing intermediate entries as necessary.
    /// Returns true if the element has been inserted successfully, false if it
    /// was already in the queue or inserted out of order.
    pub(crate) fn emplace(&mut self, packet_number: PacketNumber, entry: &T) -> bool {
        if packet_number == INVALID_PACKET_NUMBER {
            return false;
        }

        if self.is_empty() {
            self.entries.push_back(EntryWrapper { present: true, entry: entry.clone() });
            self.number_of_present_entries = 1;
            self.first_packet = packet_number;
            return true;
        }

        // Do not allow insertion out-of-order.
        if packet_number <= self.last_packet() {
            return false;
        }

        // Handle potentially missing elements.
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "insertion is rejected unless the packet number is past the last one, so the distance is a non-negative queue offset"
        )]
        let offset = (packet_number - self.first_packet) as usize;
        let gap = offset - self.entries.len();
        if gap > 0 {
            for _ in 0..gap {
                self.entries.push_back(EntryWrapper::default());
            }
        }

        self.entries.push_back(EntryWrapper { present: true, entry: entry.clone() });
        self.number_of_present_entries += 1;
        true
    }

    /// Retrieves the entry associated with the packet number, or `None` if the
    /// entry does not exist.
    pub(crate) fn get_entry(&self, packet_number: PacketNumber) -> Option<&T> {
        let offset = self.get_entry_wraper(packet_number)?;

        Some(&self.entries.offset(offset).entry)
    }

    /// Removes entries up to, but not including, `packet_number`.
    /// Unused slots in the front are also removed, which means when the function
    /// returns, `first_packet` can be larger than `packet_number`.
    pub(crate) fn remove_up_to(&mut self, packet_number: PacketNumber) {
        while !self.entries.empty() && self.first_packet != INVALID_PACKET_NUMBER && self.first_packet < packet_number {
            if self.entries.front().present {
                self.number_of_present_entries -= 1;
            }
            self.entries.pop_front();
            self.first_packet += 1;
        }
        self.clearup();
    }

    /// `IsEmpty` return if queue is empty.
    pub(crate) const fn is_empty(&self) -> bool {
        self.number_of_present_entries == 0
    }

    /// The packet number of the last entry ever inserted in the
    /// queue. Note that the entry in question may have already been removed.
    /// Zero if the queue is empty.
    pub(crate) fn last_packet(&self) -> PacketNumber {
        if self.is_empty() {
            return INVALID_PACKET_NUMBER;
        }

        #[expect(
            clippy::cast_possible_wrap,
            reason = "the ring buffer length is bounded by the queue capacity, far below the packet number range"
        )]
        let last_offset = (self.entries.len() - 1) as PacketNumber;
        self.first_packet + last_offset
    }

    pub(crate) fn clearup(&mut self) {
        while !self.entries.empty() && !self.entries.front().present {
            self.entries.pop_front();
            self.first_packet += 1;
        }
        if self.entries.empty() {
            self.first_packet = INVALID_PACKET_NUMBER;
        }
    }

    pub(crate) fn get_entry_wraper(&self, packet_number: PacketNumber) -> Option<usize> {
        if packet_number == INVALID_PACKET_NUMBER || self.is_empty() || packet_number < self.first_packet {
            return None;
        }

        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the guard above rejects a packet number below the first one, so the distance is a non-negative queue offset"
        )]
        let offset = (packet_number - self.first_packet) as usize;
        if offset >= self.entries.len() {
            return None;
        }

        if !self.entries.offset(offset).present {
            return None;
        }

        Some(offset)
    }
}
