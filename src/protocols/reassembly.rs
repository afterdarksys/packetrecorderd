use std::collections::BTreeMap;

pub struct TcpStreamReassembler {
    next_seq: u32,
    pending: BTreeMap<u32, Vec<u8>>,
    pending_bytes: usize,
    max_pending_bytes: usize,
    retransmissions: u64,
    dropped_bytes: u64,
}

impl TcpStreamReassembler {
    pub fn new(max_pending_bytes: usize, initial_seq: u32) -> Self {
        Self { next_seq: initial_seq, pending: BTreeMap::new(), pending_bytes: 0,
            max_pending_bytes, retransmissions: 0, dropped_bytes: 0 }
    }

    pub fn push(&mut self, sequence: u32, data: &[u8]) -> Vec<u8> {
        if sequence < self.next_seq {
            self.retransmissions += 1;
            return Vec::new();
        }
        if sequence > self.next_seq {
            if self.pending_bytes.saturating_add(data.len()) > self.max_pending_bytes {
                self.dropped_bytes += data.len() as u64;
            } else if self.pending.insert(sequence, data.to_vec()).is_none() {
                self.pending_bytes += data.len();
            }
            return Vec::new();
        }
        let mut output = data.to_vec();
        self.next_seq = self.next_seq.wrapping_add(data.len() as u32);
        while let Some(segment) = self.pending.remove(&self.next_seq) {
            self.pending_bytes -= segment.len();
            self.next_seq = self.next_seq.wrapping_add(segment.len() as u32);
            output.extend_from_slice(&segment);
        }
        output
    }

    pub fn has_gaps(&self) -> bool { !self.pending.is_empty() || self.dropped_bytes > 0 }
    pub fn retransmissions(&self) -> u64 { self.retransmissions }
    pub fn dropped_bytes(&self) -> u64 { self.dropped_bytes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorders_segments_and_ignores_retransmissions() {
        let mut stream = TcpStreamReassembler::new(1024, 100);
        assert!(stream.push(104, b"world").is_empty());
        assert_eq!(stream.push(100, b"hell"), b"hellworld");
        assert!(stream.push(100, b"hell").is_empty());
        assert_eq!(stream.retransmissions(), 1);
        assert!(!stream.has_gaps());
    }

    #[test]
    fn bounds_buffered_out_of_order_bytes() {
        let mut stream = TcpStreamReassembler::new(4, 100);
        stream.push(100, b"a");
        stream.push(110, b"12345");
        assert!(stream.has_gaps());
        assert!(stream.dropped_bytes() >= 5);
    }
}
