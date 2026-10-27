use bytes::Bytes;

pub(crate) type Command = u8;

pub(crate) const COMMAND_ACK: Command = 0;
pub(crate) const COMMAND_DATA: Command = 1;
pub(crate) const COMMAND_TERMINATE: Command = 2;
pub(crate) const COMMAND_PING: Command = 3;

pub(crate) type SegmentOption = u8;

pub(crate) const SEGMENT_OPTION_CLOSE: SegmentOption = 1;

pub(crate) const DATA_SEGMENT_OVERHEAD: usize = 18;

#[derive(Debug, Clone)]
pub(crate) struct DataSegment {
    pub(crate) conv: u16,
    pub(crate) option: SegmentOption,
    pub(crate) timestamp: u32,
    pub(crate) number: u32,
    pub(crate) sending_next: u32,
    pub(crate) payload: Bytes,
    pub(crate) timeout: u32,
    pub(crate) transmit: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct AckSegment {
    pub(crate) conv: u16,
    pub(crate) option: SegmentOption,
    pub(crate) receiving_window: u32,
    pub(crate) receiving_next: u32,
    pub(crate) timestamp: u32,
    pub(crate) number_list: Vec<u32>,
}

#[derive(Debug, Clone)]
pub(crate) struct CmdOnlySegment {
    pub(crate) conv: u16,
    pub(crate) cmd: Command,
    pub(crate) option: SegmentOption,
    pub(crate) sending_next: u32,
    pub(crate) receiving_next: u32,
    pub(crate) peer_rto: u32,
}

#[derive(Debug, Clone)]
pub(crate) enum Segment {
    Data(DataSegment),
    Ack(AckSegment),
    CmdOnly(CmdOnlySegment),
}

impl Segment {
    pub(crate) const fn conversation(&self) -> u16 {
        match self {
            Self::Data(s) => s.conv,
            Self::Ack(s) => s.conv,
            Self::CmdOnly(s) => s.conv,
        }
    }

    pub(crate) const fn command(&self) -> Command {
        match self {
            Self::Data(_) => COMMAND_DATA,
            Self::Ack(_) => COMMAND_ACK,
            Self::CmdOnly(s) => s.cmd,
        }
    }

    pub(crate) const fn byte_size(&self) -> usize {
        match self {
            Self::Data(s) => DATA_SEGMENT_OVERHEAD + s.payload.len(),
            Self::Ack(s) => 17 + s.number_list.len() * 4,
            Self::CmdOnly(_) => 16,
        }
    }

    /// Writes the prefix every segment shares (`conv`, `cmd`, `option`) and returns the rest of `b`,
    /// or `None` when `b` is shorter than that prefix.
    fn write_prefix(b: &mut [u8], conv: u16, cmd: Command, option: SegmentOption) -> Option<&mut [u8]> {
        let [conv_hi, conv_lo, cmd_out, option_out, rest @ ..] = b else {
            return None;
        };
        let [hi, lo] = conv.to_be_bytes();
        *conv_hi = hi;
        *conv_lo = lo;
        *cmd_out = cmd;
        *option_out = option;
        Some(rest)
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the payload length and the ack count are the 16-bit and 8-bit wire fields; the \
                  buffer is sized by `byte_size`, which bounds both to their field width"
    )]
    pub(crate) fn serialize(&self, b: &mut [u8]) {
        match self {
            Self::Data(s) => {
                let Some(rest) = Self::write_prefix(b, s.conv, COMMAND_DATA, s.option) else {
                    return;
                };
                let Some((words, tail)) = rest.split_at_mut_checked(12) else {
                    return;
                };
                for (out, value) in words.chunks_exact_mut(4).zip([s.timestamp, s.number, s.sending_next]) {
                    out.copy_from_slice(&value.to_be_bytes());
                }
                let Some((len_out, payload_out)) = tail.split_at_mut_checked(2) else {
                    return;
                };
                len_out.copy_from_slice(&(s.payload.len() as u16).to_be_bytes());
                payload_out.copy_from_slice(&s.payload);
            }
            Self::Ack(s) => {
                let Some(rest) = Self::write_prefix(b, s.conv, COMMAND_ACK, s.option) else {
                    return;
                };
                let Some((words, tail)) = rest.split_at_mut_checked(12) else {
                    return;
                };
                for (out, value) in words.chunks_exact_mut(4).zip([s.receiving_window, s.receiving_next, s.timestamp]) {
                    out.copy_from_slice(&value.to_be_bytes());
                }
                let [count_out, numbers_out @ ..] = tail else {
                    return;
                };
                *count_out = s.number_list.len() as u8;
                for (out, number) in numbers_out.chunks_exact_mut(4).zip(&s.number_list) {
                    out.copy_from_slice(&number.to_be_bytes());
                }
            }
            Self::CmdOnly(s) => {
                let Some(rest) = Self::write_prefix(b, s.conv, s.cmd, s.option) else {
                    return;
                };
                for (out, value) in rest.chunks_exact_mut(4).zip([s.sending_next, s.receiving_next, s.peer_rto]) {
                    out.copy_from_slice(&value.to_be_bytes());
                }
            }
        }
    }
}

pub(crate) fn read_segment(b: &[u8]) -> Option<(Segment, &[u8])> {
    let [conv_hi, conv_lo, cmd, opt, rest @ ..] = b else {
        return None;
    };
    let conv = u16::from_be_bytes([*conv_hi, *conv_lo]);
    match *cmd {
        COMMAND_DATA => read_data_segment(conv, *opt, rest),
        COMMAND_ACK => read_ack_segment(conv, *opt, rest),
        _ => read_cmd_only_segment(conv, *cmd, *opt, rest),
    }
}

fn read_data_segment(conv: u16, option: SegmentOption, b: &[u8]) -> Option<(Segment, &[u8])> {
    let [t0, t1, t2, t3, n0, n1, n2, n3, s0, s1, s2, s3, l0, l1, payload @ ..] = b else {
        return None;
    };
    let data_len = usize::from(u16::from_be_bytes([*l0, *l1]));
    if payload.len() < data_len {
        return None;
    }
    let (payload, extra) = payload.split_at(data_len);
    Some((
        Segment::Data(DataSegment {
            conv,
            option,
            timestamp: u32::from_be_bytes([*t0, *t1, *t2, *t3]),
            number: u32::from_be_bytes([*n0, *n1, *n2, *n3]),
            sending_next: u32::from_be_bytes([*s0, *s1, *s2, *s3]),
            payload: Bytes::copy_from_slice(payload),
            timeout: 0,
            transmit: 0,
        }),
        extra,
    ))
}

fn read_ack_segment(conv: u16, option: SegmentOption, b: &[u8]) -> Option<(Segment, &[u8])> {
    let [w0, w1, w2, w3, n0, n1, n2, n3, t0, t1, t2, t3, count, numbers @ ..] = b else {
        return None;
    };
    let count = usize::from(*count);
    if numbers.len() < count * 4 {
        return None;
    }
    let (numbers, extra) = numbers.split_at(count * 4);
    let number_list: Vec<u32> =
        numbers.chunks_exact(4).filter_map(|chunk| <[u8; 4]>::try_from(chunk).ok()).map(u32::from_be_bytes).collect();
    Some((
        Segment::Ack(AckSegment {
            conv,
            option,
            receiving_window: u32::from_be_bytes([*w0, *w1, *w2, *w3]),
            receiving_next: u32::from_be_bytes([*n0, *n1, *n2, *n3]),
            timestamp: u32::from_be_bytes([*t0, *t1, *t2, *t3]),
            number_list,
        }),
        extra,
    ))
}

fn read_cmd_only_segment(conv: u16, cmd: Command, option: SegmentOption, b: &[u8]) -> Option<(Segment, &[u8])> {
    let [s0, s1, s2, s3, r0, r1, r2, r3, p0, p1, p2, p3, rest @ ..] = b else {
        return None;
    };
    Some((
        Segment::CmdOnly(CmdOnlySegment {
            conv,
            cmd,
            option,
            sending_next: u32::from_be_bytes([*s0, *s1, *s2, *s3]),
            receiving_next: u32::from_be_bytes([*r0, *r1, *r2, *r3]),
            peer_rto: u32::from_be_bytes([*p0, *p1, *p2, *p3]),
        }),
        rest,
    ))
}
