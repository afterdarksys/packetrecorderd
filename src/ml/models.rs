use candle_core::{Tensor, Result};
use candle_nn::{Linear, Module, VarBuilder, linear};

#[derive(Clone)]
pub struct TrafficClassifier {
    layer1: Linear,
    layer2: Linear,
    layer3: Linear,
}

impl TrafficClassifier {
    pub fn new(vs: VarBuilder, in_dim: usize, out_dim: usize) -> Result<Self> {
        let layer1 = linear(in_dim, 64, vs.pp("layer1"))?;
        let layer2 = linear(64, 32, vs.pp("layer2"))?;
        let layer3 = linear(32, out_dim, vs.pp("layer3"))?;
        Ok(Self { layer1, layer2, layer3 })
    }

    pub fn forward(&self, xs: &Tensor) -> Result<Tensor> {
        let xs = self.layer1.forward(xs)?;
        let xs = xs.relu()?;
        let xs = self.layer2.forward(&xs)?;
        let xs = xs.relu()?;
        self.layer3.forward(&xs)
    }
}
