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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_default() {
        let config = Config::default();

        // Verify defaults point to Kusama Asset Hub
        assert!(config.chain_url.contains("kusama"));
        assert!(!config.mongodb_uri.is_empty());
        assert!(!config.mongodb_db.is_empty());
    }

    #[test]
    fn test_config_new() {
        let config = Config::new(
            "wss://example.com".to_string(),
            "mongodb://localhost:27017".to_string(),
            "test_db".to_string(),
        );

        assert_eq!(config.chain_url, "wss://example.com");
        assert_eq!(config.mongodb_uri, "mongodb://localhost:27017");
        assert_eq!(config.mongodb_db, "test_db");
    }

    #[test]
    fn test_config_save_load_roundtrip() {
        let original = Config::new(
            "wss://test-chain.io".to_string(),
            "mongodb://user:pass@host:27017".to_string(),
            "my_database".to_string(),
        );

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Save
        original.save_to_file(path).unwrap();

        // Load
        let loaded = Config::load_from_file(path).unwrap();

        assert_eq!(original.chain_url, loaded.chain_url);
        assert_eq!(original.mongodb_uri, loaded.mongodb_uri);
        assert_eq!(original.mongodb_db, loaded.mongodb_db);
    }

    #[test]
    fn test_config_load_invalid_json() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"not valid json").unwrap();

        let result = Config::load_from_file(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_config_load_nonexistent_file() {
        let result = Config::load_from_file(std::path::Path::new("/nonexistent/path/config.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_config_serialization_format() {
        let config = Config::new(
            "wss://chain.io".to_string(),
            "mongodb://localhost".to_string(),
            "db".to_string(),
        );

        let json = serde_json::to_string(&config).unwrap();

        // Verify JSON contains expected fields
        assert!(json.contains("chain_url"));
        assert!(json.contains("mongodb_uri"));
        assert!(json.contains("mongodb_db"));
        assert!(json.contains("wss://chain.io"));
    }
}
