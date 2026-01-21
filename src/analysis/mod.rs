use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Torch,
    Candle,
}

/// Trait for packet analysis models
pub trait PacketAnalyzer: Send + Sync {
    /// Analyze a set of features extracted from a packet
    /// Returns a vector of probabilities/scores
    fn analyze(&self, features: &[f32]) -> Result<Vec<f32>>;
}

pub mod torch;
pub mod candle;
