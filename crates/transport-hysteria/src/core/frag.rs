use super::protocol::UdpMessage;

/// The fragment counter and total are one wire byte each, so the encoder truncates to that width.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the fragment index and count are single-byte protocol fields; the encoder truncates to that width"
)]
fn frag_field(value: usize) -> u8 {
    value as u8
}

pub(crate) fn frag_udp_message(m: &UdpMessage, max_size: usize) -> Vec<UdpMessage> {
    if m.size() <= max_size {
        return vec![m.clone()];
    }
    let max_payload_size = max_size.saturating_sub(m.header_size()).max(1);
    let full_payload = &m.data;
    let frag_count = frag_field(full_payload.len().div_ceil(max_payload_size));
    full_payload
        .chunks(max_payload_size)
        .enumerate()
        .map(|(frag_id, chunk)| UdpMessage {
            session_id: m.session_id,
            host: m.host.clone(),
            port: m.port,
            msg_id: m.msg_id,
            frag_id: frag_field(frag_id),
            frag_count,
            data: chunk.to_vec(),
        })
        .collect()
}

#[derive(Default)]
pub(crate) struct Defragger {
    msg_id: u16,
    frags: Vec<Option<UdpMessage>>,
    count: u8,
}

impl Defragger {
    pub(crate) fn feed(&mut self, m: UdpMessage) -> Option<UdpMessage> {
        if m.frag_count <= 1 {
            return Some(m);
        }
        if m.frag_id >= m.frag_count {
            // wtf is this?
            return None;
        }
        let idx = usize::from(m.frag_id);
        if m.msg_id != self.msg_id {
            self.msg_id = m.msg_id;
            self.frags = vec![None; usize::from(m.frag_count)];
            self.count = 1;
            *self.frags.get_mut(idx)? = Some(m);
            return None;
        }
        let slot = self.frags.get_mut(idx)?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(m.clone());
        self.count += 1;
        if usize::from(self.count) == self.frags.len() {
            let mut data = Vec::new();
            for frag in self.frags.iter().flatten() {
                data.extend_from_slice(&frag.data);
            }
            let mut result = m;
            result.data = data;
            result.frag_id = 0;
            result.frag_count = 1;
            return Some(result);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(
        session_id: u32,
        host: &str,
        port: u16,
        msg_id: u16,
        frag_id: u8,
        frag_count: u8,
        data: &[u8],
    ) -> UdpMessage {
        UdpMessage { session_id, host: host.to_owned(), port, msg_id, frag_id, frag_count, data: data.to_vec() }
    }

    #[test]
    fn test_frag_udp_message() {
        let cases: Vec<(&str, UdpMessage, usize, Vec<UdpMessage>)> = vec![
            (
                "no frag",
                msg(123, "test", 123, 123, 0, 1, b"hello"),
                100,
                vec![msg(123, "test", 123, 123, 0, 1, b"hello")],
            ),
            (
                "2 frags",
                msg(123, "test", 123, 123, 0, 1, b"hello"),
                22,
                vec![msg(123, "test", 123, 123, 0, 2, b"hell"), msg(123, "test", 123, 123, 1, 2, b"o")],
            ),
            (
                "4 frags",
                msg(123, "test", 123, 123, 0, 1, b"wow wow wow lol lmao"),
                23,
                vec![
                    msg(123, "test", 123, 123, 0, 4, b"wow w"),
                    msg(123, "test", 123, 123, 1, 4, b"ow wo"),
                    msg(123, "test", 123, 123, 2, 4, b"w lol"),
                    msg(123, "test", 123, 123, 3, 4, b" lmao"),
                ],
            ),
        ];
        for (name, m, max_size, want) in cases {
            let got = frag_udp_message(&m, max_size);
            assert_eq!(got.len(), want.len(), "{name}");
            for (g, w) in got.iter().zip(want.iter()) {
                assert_eq!(g.session_id, w.session_id, "{name}");
                assert_eq!(g.host, w.host, "{name}");
                assert_eq!(g.port, w.port, "{name}");
                assert_eq!(g.msg_id, w.msg_id, "{name}");
                assert_eq!(g.frag_id, w.frag_id, "{name}");
                assert_eq!(g.frag_count, w.frag_count, "{name}");
                assert_eq!(g.data, w.data, "{name}");
            }
        }
    }

    /// The cases run against one shared `Defragger` in table order, so later cases depend on state
    /// left behind by earlier ones.
    #[test]
    fn test_defragger_feed() {
        let mut d = Defragger::default();
        let cases: Vec<(&str, UdpMessage, Option<UdpMessage>)> = vec![
            ("no frag", msg(123, "test", 123, 123, 0, 1, b"hello"), Some(msg(123, "test", 123, 123, 0, 1, b"hello"))),
            ("frag 1 - 1/3", msg(123, "test", 123, 666, 0, 3, b"hello"), None),
            ("frag 1 - 2/3", msg(123, "test", 123, 666, 1, 3, b" shitty "), None),
            (
                "frag 1 - 3/3",
                msg(123, "test", 123, 666, 2, 3, b"world!!"),
                Some(msg(123, "test", 123, 666, 0, 1, b"hello shitty world!!")),
            ),
            ("frag 2 - 1/2", msg(123, "test", 123, 777, 0, 2, b"hello"), None),
            ("frag 3 - 2/2", msg(123, "test", 123, 778, 1, 2, b" moto"), None),
            ("frag 2 - 2/2", msg(123, "test", 123, 777, 1, 2, b" moto"), None),
            (
                "frag 2 - 1/2 re",
                msg(123, "test", 123, 777, 0, 2, b"hello"),
                Some(msg(123, "test", 123, 777, 0, 1, b"hello moto")),
            ),
        ];
        for (name, m, want) in cases {
            let got = d.feed(m);
            match (&got, &want) {
                (None, None) => {}
                (Some(g), Some(w)) => {
                    assert_eq!(g.session_id, w.session_id, "{name}");
                    assert_eq!(g.host, w.host, "{name}");
                    assert_eq!(g.port, w.port, "{name}");
                    assert_eq!(g.msg_id, w.msg_id, "{name}");
                    assert_eq!(g.frag_id, w.frag_id, "{name}");
                    assert_eq!(g.frag_count, w.frag_count, "{name}");
                    assert_eq!(g.data, w.data, "{name}");
                }
                _ => panic!("{name}: got {got:?}, want {want:?}"),
            }
        }
    }
}
