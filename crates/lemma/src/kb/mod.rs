pub mod update;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::{
    config::{Config, kb_path},
    types::KnowledgeBase,
};

pub fn load(config: &Config) -> Result<KnowledgeBase> {
    let path = kb_path()?;

    if !path.exists() {
        bail!(
            "knowledge base not found at {}.\n\
             Run `lemma kb update` to download it.",
            path.display()
        );
    }
    let raw = std::fs::read(&path)
        .with_context(|| format!("failed to read knowledge base at {}", path.display()))?;

    if let Some(expected_hex) = config.kb.sha256.as_deref() {
        let digest = Sha256::digest(&raw);
        let actual_hex = hex::encode(digest);
        if actual_hex != expected_hex {
            bail!(
                "knowledge base digest mismatch.\n\
                 Expected: {}\n\
                 Actual:   {}\n\
                 The file may be corrupted. Run `lemma kb update` to re-download.",
                expected_hex,
                actual_hex
            );
        }
    }

    let kb: KnowledgeBase = serde_json::from_slice(&raw)
        .context("failed to parse knowledge base JSON — run `lemma kb update` to re-download")?;

    if kb.entries.is_empty() {
        bail!(
            "knowledge base at {} contains no entries.\n\
             Run `lemma kb update` to re-download.",
            path.display()
        );
    }

    if kb.embedding_dimensions == 0 {
        bail!("knowledge base has embedding_dimensions = 0, which is invalid");
    }

    let expected_dims = kb.embedding_dimensions as usize;
    if let Some(first) = kb.entries.first() {
        let actual_dims = first.embedding.len();
        if actual_dims != expected_dims {
            bail!(
                "knowledge base embedding dimension mismatch: \
                 header declares {} but first entry has {}",
                expected_dims,
                actual_dims
            );
        }
    }

    Ok(kb)
}

pub fn status_line(config: &Config) -> String {
    match (
        config.kb.version.as_deref(),
        config.kb.last_updated.as_deref(),
    ) {
        (Some(v), Some(ts)) => format!("version {} (updated {})", v, &ts[..10]),
        (Some(v), None) => format!("version {} (update time unknown)", v),
        (None, _) => "not downloaded — run `lemma kb update`".to_string(),
    }
}
