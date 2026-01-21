#![allow(dead_code)]
// Decoders module - for higher level session reconstruction
pub trait Decoder {
    fn decode(&self, data: &[u8]) -> Vec<u8>;
}
