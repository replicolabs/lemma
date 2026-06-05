use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const LEMMA_DIR_NAME: &str = ".lemma";
const CONFIG_FILE_NAME: &str = "config.toml";
const KB_FILE_NAME: &str = "knowledge_base.json";
const KB_LOCK_FILE_NAME: &str = "kb.lock";

pub const KB_LATEST_VERSION_URL: &str =
    "https://github.com/replicolabs/kb/releases/latest/download/latest_version.txt";
pub const KB_LATEST_DOWNLOAD_URL: &str =
    "https://github.com/replicolabs/kb/releases/latest/download/knowledge_base.json";


#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub voyage: VoyageConfig,

    #[serde(default)]
    pub kb: KbConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VoyageConfig {
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KbConfig {
    pub version: Option<String>,
    pub sha256: Option<String>,
    pub last_updated: Option<String>,
    pub download_url: Option<String>,
}

pub fn lemma_dir() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .context("could not determine home directory")?;
    Ok(home.join(LEMMA_DIR_NAME))
}

pub fn config_path() -> Result<PathBuf> {
    Ok(lemma_dir()?.join(CONFIG_FILE_NAME))
}

pub fn kb_path() -> Result<PathBuf> {
    Ok(lemma_dir()?.join(KB_FILE_NAME))
}

/// Returns the path to `~/.lemma/kb.lock`.
pub fn kb_lock_path() -> Result<PathBuf> {
    Ok(lemma_dir()?.join(KB_LOCK_FILE_NAME))
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = config_path()?;

        let mut config = if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read config at {}", path.display()))?;
            toml::from_str::<Config>(&raw)
                .with_context(|| format!("failed to parse config at {}", path.display()))?
        } else {
            Config::default()
        };

        if let Ok(key) = std::env::var("VOYAGE_API_KEY") {
            if !key.is_empty() {
                config.voyage.api_key = Some(key);
            }
        }

        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let dir  = lemma_dir()?;
        let path = dir.join(CONFIG_FILE_NAME);

        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create lemma directory at {}", dir.display()))?;

        let contents = toml::to_string_pretty(self)
            .context("failed to serialise config")?;

        std::fs::write(&path, contents)
            .with_context(|| format!("failed to write config to {}", path.display()))?;

        Ok(())
    }

    pub fn voyage_api_key(&self) -> Option<&str> {
        self.voyage.api_key.as_deref()
    }

    pub fn is_initialised(&self) -> bool {
        self.voyage.api_key.as_deref().is_some_and(|k| !k.is_empty())
    }

    pub fn set_kb_version(
        &mut self,
        version: impl Into<String>,
        sha256:  impl Into<String>,
    ) {
        let now = chrono::Utc::now().to_rfc3339();
        self.kb.version      = Some(version.into());
        self.kb.sha256       = Some(sha256.into());
        self.kb.last_updated = Some(now);
    }

    pub fn kb_download_url(&self) -> &str {
        self.kb
            .download_url
            .as_deref()
            .unwrap_or(KB_LATEST_DOWNLOAD_URL)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbLock {
    pub version:      String,
    pub url:          String,
    pub sha256:       String,
    pub downloaded_at: String,
}

impl KbLock {
    pub fn write(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self)
            .context("failed to serialise kb.lock")?;
        std::fs::write(path, contents)
            .with_context(|| format!("failed to write kb.lock to {}", path.display()))?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read kb.lock at {}", path.display()))?;
        let lock = toml::from_str(&raw)
            .with_context(|| format!("failed to parse kb.lock at {}", path.display()))?;
        Ok(Some(lock))
    }
}
