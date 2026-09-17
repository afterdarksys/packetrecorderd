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
        let relative = sequence.wrapping_sub(self.next_seq) as i32;
        let data = if relative < 0 {
            let overlap = self.next_seq.wrapping_sub(sequence) as usize;
            self.retransmissions += 1;
            if overlap >= data.len() {
                return Vec::new();
            }
            &data[overlap..]
        } else {
            data
        };
        let sequence = if relative < 0 { self.next_seq } else { sequence };

        if relative > 0 {
            if self.pending_bytes.saturating_add(data.len()) > self.max_pending_bytes {
                self.dropped_bytes += data.len() as u64;
            } else {
                if let Some(replaced) = self.pending.insert(sequence, data.to_vec()) {
                    self.pending_bytes -= replaced.len();
                }
                self.pending_bytes += data.len();
            }
            return Vec::new();
        }
        let mut output = data.to_vec();
        self.next_seq = self.next_seq.wrapping_add(data.len() as u32);
        loop {
            let Some((&segment_seq, _)) = self.pending.iter().find(|(seq, _)|
                (**seq).wrapping_sub(self.next_seq) as i32 <= 0
            ) else { break };
            let segment = self.pending.remove(&segment_seq).expect("pending segment disappeared");
            self.pending_bytes -= segment.len();
            let overlap = self.next_seq.wrapping_sub(segment_seq) as usize;
            if overlap >= segment.len() {
                self.retransmissions += 1;
                continue;
            }
            let tail = &segment[overlap..];
            self.next_seq = self.next_seq.wrapping_add(tail.len() as u32);
            output.extend_from_slice(tail);
        }
        output
    }

    pub fn has_gaps(&self) -> bool { !self.pending.is_empty() || self.dropped_bytes > 0 }
    pub fn retransmissions(&self) -> u64 { self.retransmissions }
    pub fn dropped_bytes(&self) -> u64 { self.dropped_bytes }
    pub fn pending_bytes(&self) -> usize { self.pending_bytes }
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

    #[test]
    fn accepts_in_order_data_across_sequence_wraparound() {
        let mut stream = TcpStreamReassembler::new(1024, u32::MAX - 1);
        assert!(stream.push(1, b"def").is_empty());
        assert_eq!(stream.push(u32::MAX - 1, b"abc"), b"abcdef");
    }

    #[test]
    fn preserves_unseen_tail_of_overlapping_segment() {
        let mut stream = TcpStreamReassembler::new(1024, 100);
        assert_eq!(stream.push(100, b"hello"), b"hello");
        assert_eq!(stream.push(103, b"lo world"), b" world");
    }

    #[test]
    fn replacing_pending_segment_keeps_byte_accounting_consistent() {
        let mut stream = TcpStreamReassembler::new(1024, 100);
        assert!(stream.push(105, b"x").is_empty());
        assert!(stream.push(105, b"world").is_empty());
        assert_eq!(stream.push(100, b"hello"), b"helloworld");
        assert_eq!(stream.pending_bytes, 0);
    }

    #[test]
    fn removes_pending_segment_fully_covered_by_later_contiguous_data() {
        let mut stream = TcpStreamReassembler::new(1024, 100);
        assert!(stream.push(105, b"world").is_empty());
        assert_eq!(stream.push(100, b"hello!!!!!"), b"hello!!!!!");
        assert_eq!(stream.pending_bytes, 0);
        assert!(!stream.has_gaps());
    }
}
