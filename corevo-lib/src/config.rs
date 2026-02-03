use serde::{Deserialize, Serialize};

/// Configuration for CoReVo library
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// WebSocket URL for the Substrate chain
    /// e.g., "wss://sys.ibp.network/asset-hub-kusama:443"
    pub chain_url: String,

    /// MongoDB connection URI
    /// e.g., "mongodb://readonly:123456@host:27017/?directConnection=true"
    pub mongodb_uri: String,

    /// MongoDB database name
    /// e.g., "litescan_kusama_assethub"
    pub mongodb_db: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_url: "wss://sys.ibp.network/asset-hub-kusama:443".to_string(),
            mongodb_uri: "mongodb://readonly:123456@62.84.182.186:27017/?directConnection=true"
                .to_string(),
            mongodb_db: "litescan_kusama_assethub".to_string(),
        }
    }
}

impl Config {
    pub fn new(chain_url: String, mongodb_uri: String, mongodb_db: String) -> Self {
        Self {
            chain_url,
            mongodb_uri,
            mongodb_db,
        }
    }

    /// Load configuration from a JSON file
    pub fn load_from_file(path: &std::path::Path) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content).map_err(|e| {
            crate::error::CorevoError::Config(format!("Failed to parse config: {}", e))
        })
    }

    /// Save configuration to a JSON file
    pub fn save_to_file(&self, path: &std::path::Path) -> crate::error::Result<()> {
        let content = serde_json::to_string_pretty(self).map_err(|e| {
            crate::error::CorevoError::Config(format!("Failed to serialize config: {}", e))
        })?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
