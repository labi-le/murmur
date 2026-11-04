use std::borrow::Cow;
use std::time::Duration;

use anyhow::{anyhow, Result};
use hickory_proto::op::{Header, Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Stream;
use murmur_common_pool as pool;

use super::service::serve_msg;

pub const DEFAULT_DNS_READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_DNS_RELAY_TIMEOUT: Duration = Duration::from_secs(5);
pub const SAFE_DNS_PACKET_SIZE: usize = 2 * 1024;
const MIN_MSG_SIZE: usize = 512;

/// The UDP payload size a reply to `msg` may occupy.
#[must_use]
pub fn request_udp_size(msg: &Message) -> usize {
    match &msg.edns {
        Some(opt) => usize::from(opt.max_payload()),
        None => MIN_MSG_SIZE,
    }
}

pub async fn relay_dns_conn(ctx: &CancellationToken, mut conn: Box<dyn Stream>, read_timeout: Duration) -> Result<()> {
    let mut buff = pool::get(pool::UDP_BUFFER_SIZE);
    let result = relay_dns_conn_loop(ctx, &mut *conn, read_timeout, &mut buff).await;
    let _ = pool::put(buff);
    let _ = conn.shutdown_read();
    let _ = conn.shutdown_write();
    result
}

/// Reads the two-byte big-endian length prefix and the message body it announces into `buff`,
/// returning the message length. A too-large announced length is reported the same way a read
/// failure is: the caller treats both as "stop relaying", matching the loop, which never
/// distinguishes the two.
// NOT cancel-safe: a read cut short mid-message consumes part of it and desynchronizes the
// stream, so the caller closes the connection instead of resuming the read.
async fn read_length_prefixed_message(conn: &mut dyn Stream, buff: &mut [u8]) -> std::io::Result<usize> {
    let mut length_bytes = [0u8; 2];
    conn.read_exact(&mut length_bytes).await?;
    let length = usize::from(u16::from_be_bytes(length_bytes));
    if length > buff.len() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "dns: reply exceeds the read buffer"));
    }
    let (message, _) = buff.split_at_mut(length);
    conn.read_exact(message).await?;
    Ok(length)
}

// cancel-safe: the caller closes the connection it owns, and the loop keeps no state beyond the
// borrowed read buffer.
async fn relay_dns_conn_loop(
    ctx: &CancellationToken,
    conn: &mut dyn Stream,
    read_timeout: Duration,
    buff: &mut [u8],
) -> Result<()> {
    loop {
        let read = read_length_prefixed_message(conn, buff);
        let length = if read_timeout > Duration::ZERO {
            match tokio::time::timeout(read_timeout, read).await {
                Ok(Ok(length)) => length,
                Ok(Err(_)) | Err(_) => break,
            }
        } else {
            match read.await {
                Ok(length) => length,
                Err(_) => break,
            }
        };

        let Some(packet) = buff.get(..length) else {
            break;
        };
        let msg = Message::from_vec(packet)?;

        let relay_ctx = ctx.child_token();
        let timeout_ctx = relay_ctx.clone();
        let _timeout = tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(DEFAULT_DNS_RELAY_TIMEOUT) => timeout_ctx.cancel(),
                () = timeout_ctx.cancelled() => {}
            }
        });

        let Some(target) = buff.get_mut(2..) else {
            break;
        };
        let reply = relay_dns_msg(&relay_ctx, &msg, target, 0).await;
        relay_ctx.cancel();
        let reply = reply?;

        let reply_len = reply.len();
        let Ok(data_len) = u16::try_from(reply_len) else {
            return Err(anyhow!("dns: reply of {reply_len} bytes exceeds the length prefix"));
        };
        let in_target = match reply {
            Cow::Borrowed(_) => None,
            Cow::Owned(data) => Some(data),
        };
        match in_target {
            None => {
                let Some(head) = buff.get_mut(..2) else {
                    break;
                };
                head.copy_from_slice(&data_len.to_be_bytes());
                let Some(packet) = buff.get(..2 + reply_len) else {
                    break;
                };
                conn.write_all(packet).await?;
            }
            Some(data) => {
                let mut new_buff = pool::get(reply_len + 2);
                let Some(head) = new_buff.get_mut(..2) else {
                    break;
                };
                head.copy_from_slice(&data_len.to_be_bytes());
                let Some(body) = new_buff.get_mut(2..2 + reply_len) else {
                    break;
                };
                body.copy_from_slice(&data);
                let Some(packet) = new_buff.get(..2 + reply_len) else {
                    break;
                };
                conn.write_all(packet).await?;
                let _ = pool::put(new_buff);
            }
        }
    }
    Ok(())
}

/// Truncates udp messages up to [`SAFE_DNS_PACKET_SIZE`].
///
/// The returned slice either aliases `target` or is a freshly allocated buffer, hence
/// `Cow::Borrowed`/`Cow::Owned`.
pub async fn relay_dns_packet<'a>(
    ctx: &CancellationToken,
    payload: &[u8],
    target: &'a mut [u8],
) -> Result<Cow<'a, [u8]>> {
    relay_dns_packet_inner(ctx, payload, target, SAFE_DNS_PACKET_SIZE).await
}

async fn relay_dns_packet_inner<'a>(
    ctx: &CancellationToken,
    payload: &[u8],
    target: &'a mut [u8],
    max_size: usize,
) -> Result<Cow<'a, [u8]>> {
    let msg = Message::from_vec(payload)?;
    relay_dns_msg(ctx, &msg, target, max_size).await
}

async fn relay_dns_msg<'a>(
    ctx: &CancellationToken,
    msg: &Message,
    target: &'a mut [u8],
    max_size: usize,
) -> Result<Cow<'a, [u8]>> {
    let Ok(mut reply) = serve_msg(ctx, msg).await else {
        let mut failure = Message::new(0, MessageType::Query, OpCode::Query);
        set_rcode(&mut failure, msg, ResponseCode::ServFail);
        return pack_buffer(&failure, target);
    };

    let rcode = reply.metadata.response_code;
    set_rcode(&mut reply, msg, rcode);
    if max_size > 0 {
        let mut max_size = max_size;
        let size = request_udp_size(msg);
        if size < max_size {
            max_size = size;
        }
        truncate(&mut reply, max_size);
    }
    pack_buffer(&reply, target)
}

/// Sets the reply metadata, then the response code.
pub fn set_rcode(msg: &mut Message, request: &Message, rcode: ResponseCode) {
    msg.metadata = Metadata::response_from_request(&request.metadata);
    if let Some(question) = request.queries.first() {
        msg.queries = vec![question.clone()];
    }
    msg.metadata.response_code = rcode;
}

/// Keeps the longest prefix of the answer, authority and additional
/// sections that encodes within `size` and reports the loss through the TC bit.
///
/// Each record is encoded with no size limit over hickory's own compressing encoder, and the
/// running offset, which already reflects name compression, is compared with the budget
/// afterwards. A record that takes the offset past the budget is dropped and closes every later
/// section; one that lands exactly on the budget is kept and also closes them, since every later
/// record is gated on the offset still being under the budget.
pub fn truncate(msg: &mut Message, size: usize) {
    if msg.signature.is_some() {
        return;
    }
    let size = size.max(MIN_MSG_SIZE);
    if encoded_len(msg) <= size {
        return;
    }

    let edns_len = msg.edns.as_ref().map_or(0, edns_record_len);
    let budget = size.saturating_sub(edns_len);

    let mut buffer = Vec::with_capacity(budget.min(512));
    let mut encoder = BinEncoder::new(&mut buffer);

    let mut open =
        encoder.place::<Header>().is_ok() && encoder.emit_all(msg.queries.iter()).is_ok() && encoder.offset() < budget;

    let mut answer_count = 0;
    let mut authority_count = 0;
    let mut additional_count = 0;

    if open {
        (answer_count, open) = emit_section(&mut encoder, &msg.answers, budget);
    }
    if open {
        (authority_count, open) = emit_section(&mut encoder, &msg.authorities, budget);
    }
    if open {
        (additional_count, _) = emit_section(&mut encoder, &msg.additionals, budget);
    }

    let dropped = answer_count < msg.answers.len()
        || authority_count < msg.authorities.len()
        || additional_count < msg.additionals.len();

    msg.answers.truncate(answer_count);
    msg.authorities.truncate(authority_count);
    msg.additionals.truncate(additional_count);
    msg.metadata.truncation = msg.metadata.truncation || dropped;
}

/// Returns how many of `records` are kept and whether a later section may
/// still be attempted. An encode error (never observed for records already accepted into a
/// `Message`) stops the section at that record and closes the rest.
fn emit_section(encoder: &mut BinEncoder<'_>, records: &[Record], budget: usize) -> (usize, bool) {
    for (i, record) in records.iter().enumerate() {
        if record.emit(encoder).is_err() {
            return (i, false);
        }
        let offset = encoder.offset();
        if offset > budget {
            return (i, false);
        }
        if offset == budget {
            return (i + 1, false);
        }
    }
    (records.len(), encoder.offset() < budget)
}

/// The wire length of the OPT record `edns` would encode to, the length used to
/// reserve room for the EDNS record so it is never dropped by truncation.
fn edns_record_len(edns: &hickory_proto::op::Edns) -> usize {
    let record = Record::from(edns);
    let mut buf = Vec::with_capacity(32);
    let mut encoder = BinEncoder::new(&mut buf);
    if record.emit(&mut encoder).is_err() {
        return 0;
    }
    encoder.len()
}

/// The encoded reply lands in `target` when it fits there, otherwise in
/// a fresh buffer, matching the two cases the callers branch on.
fn pack_buffer<'a>(msg: &Message, target: &'a mut [u8]) -> Result<Cow<'a, [u8]>> {
    let data = msg.to_vec()?;
    let Some(slot) = target.get_mut(..data.len()) else {
        return Ok(Cow::Owned(data));
    };
    slot.copy_from_slice(&data);
    let filled: &'a [u8] = slot;
    Ok(Cow::Borrowed(filled))
}

fn encoded_len(msg: &Message) -> usize {
    msg.to_vec().map_or(usize::MAX, |data| data.len())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use hickory_proto::op::{Edns, Query};
    use hickory_proto::rr::rdata::opt::EdnsOption;
    use hickory_proto::rr::rdata::{A, NS, TXT};
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use tokio_util::sync::CancellationToken;

    use super::{relay_dns_conn_loop, truncate, Duration, Message, MessageType, OpCode, Stream, SAFE_DNS_PACKET_SIZE};

    fn message_with_answers(n: u32) -> Message {
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(Name::from_str("example.com.").unwrap(), RecordType::A));
        for i in 0..n {
            let name = Name::from_str(&format!("host{i}.example.com.")).unwrap();
            let addr = Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8);
            msg.answers.push(Record::from_rdata(name, 60, RData::A(A(addr))));
        }
        msg
    }

    /// Truncating to 512 bytes on this exact message (50 `hostN.example.com.` A answers
    /// behind an `example.com. A` question) keeps 21 answers and packs to 502 bytes.
    #[test]
    fn truncate_keeps_the_reference_answer_count_and_wire_size() {
        let mut msg = message_with_answers(50);
        truncate(&mut msg, 512);
        assert_eq!(msg.answers.len(), 21, "kept answer count must match miekg dns v1.1.63 Truncate(512)");
        assert!(msg.metadata.truncation);
        let packed = msg.to_vec().expect("packs");
        assert_eq!(packed.len(), 502, "packed wire size must match miekg dns v1.1.63 Truncate(512)");
    }

    /// Each record is counted at its compressed length, so a record whose owner
    /// name compresses to a pointer is kept whenever the pointer form fits, even when its
    /// uncompressed labels would not. The kept prefix must therefore be the longest one that packs
    /// within `size`.
    #[test]
    fn truncate_counts_records_at_their_compressed_length() {
        let owner = Name::from_str("a-long-label-that-compresses-to-a-pointer-0123456789.example.com.").unwrap();
        let mut original = Message::new(1, MessageType::Response, OpCode::Query);
        original.queries.push(Query::query(owner.clone(), RecordType::A));
        for i in 0..40u8 {
            original.answers.push(Record::from_rdata(owner.clone(), 60, RData::A(A(Ipv4Addr::new(10, 0, 0, i)))));
        }
        let packed_len = |answers: usize| {
            let mut prefix = original.clone();
            prefix.answers.truncate(answers);
            prefix.to_vec().expect("packs").len()
        };
        for size in 512..=700 {
            let mut msg = original.clone();
            truncate(&mut msg, size);
            let kept = msg.answers.len();
            assert!(packed_len(kept) <= size, "size {size}: kept prefix of {kept} overflows");
            assert!(
                kept == original.answers.len() || packed_len(kept + 1) > size,
                "size {size}: kept {kept} answers but {} fit",
                kept + 1
            );
        }
    }

    #[test]
    fn truncate_keeps_prefix_and_sets_tc() {
        let original = message_with_answers(50);
        let mut msg = original.clone();
        truncate(&mut msg, 512);
        assert!(msg.metadata.truncation);
        assert!(!msg.answers.is_empty());
        assert!(msg.answers.len() < 50);
        for (kept, original) in msg.answers.iter().zip(original.answers.iter()) {
            assert_eq!(kept.data, original.data);
        }
    }

    /// Once the answer section itself had to be cut, the `if l < size` gates never let the
    /// authority or additional sections contribute anything, even though — as here — there would
    /// still be room left in the raw byte budget for the small NS/glue records that follow a
    /// single oversized dropped answer.
    ///
    /// Truncating to 512 bytes on 5 `aN.example.com.` A answers
    /// plus one `big.example.com.` TXT answer (two 255-byte character-strings), one
    /// `example.com. NS ns1.example.com.` authority, and one `ns1.example.com. A` glue additional
    /// keeps answers=5, ns=0, extra=0 and packs to 124 bytes.
    #[test]
    fn truncate_drops_authority_and_additional_once_answers_are_cut() {
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.queries.push(Query::query(Name::from_str("example.com.").unwrap(), RecordType::A));
        for i in 0..5u8 {
            let name = Name::from_str(&format!("a{i}.example.com.")).unwrap();
            msg.answers.push(Record::from_rdata(name, 60, RData::A(A(Ipv4Addr::new(10, 0, 0, i + 1)))));
        }
        let txt_name = Name::from_str("big.example.com.").unwrap();
        let txt_data = vec!["x".repeat(255), "y".repeat(255)];
        msg.answers.push(Record::from_rdata(txt_name, 60, RData::TXT(TXT::new(txt_data))));
        let ns_name = Name::from_str("example.com.").unwrap();
        let ns_target = Name::from_str("ns1.example.com.").unwrap();
        msg.authorities.push(Record::from_rdata(ns_name, 60, RData::NS(NS(ns_target))));
        let glue_name = Name::from_str("ns1.example.com.").unwrap();
        msg.additionals.push(Record::from_rdata(glue_name, 60, RData::A(A(Ipv4Addr::new(10, 0, 0, 10)))));

        truncate(&mut msg, 512);

        assert_eq!(msg.answers.len(), 5, "answer section must keep only the 5 A records");
        assert_eq!(msg.authorities.len(), 0, "authority section must be dropped once the answer section was cut");
        assert_eq!(msg.additionals.len(), 0, "additional section must be dropped once the answer section was cut");
        assert!(msg.metadata.truncation);
        let packed = msg.to_vec().expect("packs");
        assert_eq!(packed.len(), 124, "packed wire size must match miekg dns v1.1.63 Truncate(512)");
    }

    /// The header and question section are never truncated; when even those, together with a
    /// mandatory EDNS OPT record, cannot fit the requested size, every answer/authority/additional
    /// record is dropped and TC is set, rather than the message being returned unchanged.
    #[test]
    fn truncate_drops_everything_when_header_and_edns_exceed_budget() {
        let mut msg = message_with_answers(5);
        let mut edns = Edns::new();
        edns.options_mut().insert(EdnsOption::Unknown(65001, vec![0u8; 600]));
        msg.edns = Some(edns);

        truncate(&mut msg, 512);

        assert!(msg.answers.is_empty(), "every answer must be dropped once header+EDNS alone exceed the budget");
        assert!(msg.metadata.truncation);
    }

    struct TestStream(tokio::io::DuplexStream);

    impl tokio::io::AsyncRead for TestStream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for TestStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Stream for TestStream {
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    /// A per-iteration read deadline became a `tokio::time::timeout` wrapping the whole
    /// length-prefix-plus-body read; this proves the loop actually stops once the deadline
    /// elapses instead of blocking forever on a peer that never sends anything.
    #[tokio::test]
    async fn relay_dns_conn_loop_stops_after_read_timeout_elapses() {
        let (_writer, reader) = tokio::io::duplex(64);
        let mut conn = TestStream(reader);
        let ctx = CancellationToken::new();
        let mut buff = vec![0u8; 4096];
        let start = tokio::time::Instant::now();
        let result = relay_dns_conn_loop(&ctx, &mut conn, Duration::from_millis(50), &mut buff).await;
        assert!(result.is_ok(), "a read timeout must end the loop cleanly, not surface as an error");
        assert!(start.elapsed() >= Duration::from_millis(50), "loop must wait out the read timeout before giving up");
    }

    #[test]
    fn truncate_no_op_when_answer_already_fits() {
        let mut msg = message_with_answers(1);
        let before = msg.answers.len();
        truncate(&mut msg, SAFE_DNS_PACKET_SIZE);
        assert!(!msg.metadata.truncation);
        assert_eq!(msg.answers.len(), before);
    }
}
