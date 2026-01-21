use anyhow::{Context, Result};
use tch::{CModule, Tensor};
use super::PacketAnalyzer;

pub struct TorchModel {
    model: CModule,
}

impl TorchModel {
    pub fn new(path: &str) -> Result<Self> {
        let model = CModule::load(path)
            .context("Failed to load TorchScript model")?;
        Ok(Self { model })
    }
}

impl PacketAnalyzer for TorchModel {
    fn analyze(&self, features: &[f32]) -> Result<Vec<f32>> {
        // Create a tensor from the input features
        // Assuming features is a flat 1D array, we unsqueeze to add batch dimension
        let tensor = Tensor::from_slice(features).unsqueeze(0);
        
        // Forward pass
        let output = self.model.forward_ts(&[&tensor])?;
        
        // Convert output tensor back to Vec<f32>
        // Depending on output shape, this might need adjustment. 
        // Assuming output is [1, num_classes] or [num_classes]
        let scores = Vec::<f32>::from(&output);
        Ok(scores)
    }
}
