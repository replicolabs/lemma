use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use futures_util::StreamExt;

use crate::config::{kb_lock_path, kb_path, Config, KB_LATEST_VERSION_URL, KbLock};

const VERSION_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
const USER_AGENT: &str = concat!("lemma/", env!("CARGO_PKG_VERSION"));

pub async fn run(config: &mut Config, force: bool) -> Result<()> {
    let client = build_client()?;
    println!("Checking for knowledge base updates…");

    let remote_version = fetch_latest_version(&client).await?;
    let local_version  = config.kb.version.as_deref().unwrap_or("none");

    if !force && remote_version == local_version {
        println!(
            "Knowledge base is already up to date (version {}).",
            local_version
        );
        return Ok(());
    }

    if local_version != "none" {
        println!(
            "Updating: {} → {}",
            local_version, remote_version
        );
    } else {
        println!("Downloading knowledge base version {}…", remote_version);
    }
    let download_url = config.kb_download_url();
    let (bytes, sha256_hex) = download_with_progress(&client, download_url).await?;
    validate_json(&bytes)?;
    let kb_path = kb_path()?;
    if let Some(parent) = kb_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| {
                format!("failed to create lemma directory at {}", parent.display())
            })?;
    }

    let mut file = tokio::fs::File::create(&kb_path)
        .await
        .with_context(|| format!("failed to create file at {}", kb_path.display()))?;

    file.write_all(&bytes)
        .await
        .with_context(|| format!("failed to write knowledge base to {}", kb_path.display()))?;

    file.flush().await.context("failed to flush knowledge base file")?;
    config.set_kb_version(&remote_version, &sha256_hex);
    config.save().context("failed to save config after kb update")?;
    let lock = KbLock {
        version:       remote_version.clone(),
        url:           config.kb_download_url().to_string(),
        sha256:        sha256_hex.clone(),
        downloaded_at: chrono::Utc::now().to_rfc3339(),
    };
    if let Ok(lock_path) = kb_lock_path() {
        let _ = lock.write(&lock_path);
    }

    println!(
        "✓ Knowledge base updated to version {} ({:.1} MB)",
        remote_version,
        bytes.len() as f64 / 1_048_576.0,
    );
    println!(
        "  SHA-256: {}",
        &sha256_hex[..16]
    );

    Ok(())
}


fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .context("failed to build HTTP client")
}

async fn fetch_latest_version(client: &Client) -> Result<String> {
    let response = client
        .get(KB_LATEST_VERSION_URL)
        .timeout(VERSION_CHECK_TIMEOUT)
        .send()
        .await
        .context(
            "failed to reach GitHub to check for updates.\n\
             Check your internet connection and try again.",
        )?;

    if !response.status().is_success() {
        let status = response.status();
        bail!(
            "version check request returned HTTP {}.\n\
             If this persists, check https://github.com/replicolabs/kb/releases",
            status
        );
    }

    let text = response
        .text()
        .await
        .context("failed to read version response body")?;

    let version = text.trim().to_string();
    if version.is_empty() {
        bail!("remote version file is empty — this is a bug in the knowledge base release pipeline");
    }

    Ok(version)
}

async fn download_with_progress(
    client: &Client,
    url:    &str,
) -> Result<(Vec<u8>, String)> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| {
            format!(
                "failed to download knowledge base from {}.\n\
                 Check your internet connection.",
                url
            )
        })?;

    if !response.status().is_success() {
        let status = response.status();
        bail!(
            "download request returned HTTP {}.\n\
             URL: {}",
            status,
            url
        );
    }

    let content_length = response.content_length();
    let pb = build_progress_bar(content_length);

    let mut hasher  = Sha256::new();
    let capacity    = content_length.unwrap_or(2 * 1024 * 1024) as usize;
    let mut buf     = Vec::with_capacity(capacity);

    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("error while downloading knowledge base")?;
        hasher.update(&chunk);
        pb.inc(chunk.len() as u64);
        buf.extend_from_slice(&chunk);
    }

    pb.finish_and_clear();

    let digest  = hasher.finalize();
    let hex     = hex::encode(digest);

    Ok((buf, hex))
}

fn validate_json(bytes: &[u8]) -> Result<()> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .context(
            "downloaded file is not valid JSON — the release may be corrupted.\n\
             Try running `lemma kb update` again.",
        )?;
    Ok(())
}

fn build_progress_bar(total_bytes: Option<u64>) -> ProgressBar {
    match total_bytes {
        Some(n) => {
            let pb = ProgressBar::new(n);
            pb.set_style(
                ProgressStyle::with_template(
                    "  [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
                )
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=>-"),
            );
            pb
        }
        None => {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::with_template("  {spinner:.cyan} {bytes} downloaded")
                    .unwrap_or_else(|_| ProgressStyle::default_spinner()),
            );
            pb
        }
    }
}
