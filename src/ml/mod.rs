pub mod models;

use anyhow::Result;
use candle_core::{Device, Tensor};
use candle_nn::VarBuilder;
// use hf_hub::{api::sync::Api, Repo, RepoType};
use models::TrafficClassifier;
use std::sync::Arc;
use tracing::{info, error, warn};
use crate::model_client::ModelApiClient;

#[derive(Clone)]
pub struct MLProcessor {
    classifier: Option<Arc<TrafficClassifier>>,
    device: Device,
    client: Option<Arc<ModelApiClient>>,
}

impl MLProcessor {
    pub fn new(client: Option<Arc<ModelApiClient>>) -> Self {
        let device = Device::Cpu; // Default to CPU for broad compatibility
        Self {
            classifier: None,
            device,
            client,
        }
    }

    pub fn load_models(&mut self) -> Result<()> {
        info!("Loading ML models...");
        
        // In a real scenario, we would download a specific pretrained model.
        // For this implementation, we'll initialize a dummy model structure 
        // effectively acting as a placeholder until weights are available.
        // Or we could try to download a demo model if one existed.
        
        // Uncomment below when a real model exists on HF Hub
        // Check for model updates if client is available
        if let Some(client) = &self.client {
            info!("Checking for model updates...");
            // We spawn this to not block, or just await if we were async. 
            // Since this is sync and load_models returns Result, we'll just check manifest
            // In a real app we'd need an async runtime handle here or block_on
            // For now, we'll use a blocking runtime for this init step if needed, 
            // or just note that we would fetch:
            
            // To actually use the code to satisfy the compiler:
            let client_clone = client.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                
                rt.block_on(async {
                    match client_clone.fetch_manifest().await {
                        Ok(manifest) => {
                            info!("Found model manifest: version {}", manifest.version);
                            // Here we would download artifacts using client.artifact_url()
                        },
                        Err(e) => {
                            warn!("Failed to fetch model manifest: {}", e);
                        }
                    }
                });
            });
        }

        /*
        let api = Api::new()?;
        let repo = api.repo(Repo::new("packetrecorder/traffic-classifier".to_string(), RepoType::Model));
        let weights = repo.get("model.safetensors")?;
        
        let vb = unsafe { VarBuilder::from_mmaped_safetensors(&[weights], DType::F32, &self.device)? };
        */

        // For now, initialize random weights for demonstration/integration
        let vb = VarBuilder::zeros(candle_core::DType::F32, &self.device);
        
        match TrafficClassifier::new(vb, 10, 5) { // 10 input features, 5 protocol classes
            Ok(model) => {
                self.classifier = Some(Arc::new(model));
                info!("TrafficClassifier loaded successfully");
            },
            Err(e) => {
                error!("Failed to initialize TrafficClassifier: {:?}", e);
            }
        }

        Ok(())
    }

    pub fn predict_protocol(&self, features: &[f32]) -> Option<String> {
        let Some(classifier) = &self.classifier else {
            return None;
        };

        match Tensor::from_slice(features, (1, features.len()), &self.device) {
            Ok(input) => {
                if let Ok(output) = classifier.forward(&input) {
                    if let Ok(probs) = candle_nn::ops::softmax(&output, 1) {
                        if let Ok(vec) = probs.to_vec2::<f32>() {
                            if let Some(top_class) = vec[0].iter().enumerate().max_by(|a, b| a.1.partial_cmp(b.1).unwrap()) {
                                // Simplified mapping
                                let protocols = ["HTTP", "DNS", "TLS", "SSH", "Unknown"];
                                if top_class.0 < protocols.len() {
                                    return Some(protocols[top_class.0].to_string());
                                }
                            }
                        }
                    }
                }
            },
            Err(e) => {
                error!("Inference error: {:?}", e);
            }
        }
        
        None
    }
}
