use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const EMBED_TIMEOUT: Duration = Duration::from_secs(30);
const VOYAGE_EMBED_URL: &str = "https://api.voyageai.com/v1/embeddings";
const USER_AGENT: &str = concat!("lemma/", env!("CARGO_PKG_VERSION"));

#[derive(Serialize)]
struct EmbedRequest<'a> {
    model: &'a str,
    input: &'a [&'a str],
    input_type: &'a str,
}

#[derive(Deserialize)]
struct EmbedResponse {
    data: Vec<EmbedData>,
}

#[derive(Deserialize)]
struct EmbedData {
    embedding: Vec<f32>,
    index: usize,
}

pub async fn embed_query(query: &str, model: &str, api_key: &str) -> Result<Vec<f32>> {
    let client = build_client()?;
    embed_one(&client, query, model, api_key).await
}

pub async fn embed_batch(texts: &[&str], model: &str, api_key: &str) -> Result<Vec<Vec<f32>>> {
    if texts.is_empty() {
        return Ok(Vec::new());
    }

    let client = build_client()?;
    let body = EmbedRequest {
        model,
        input: texts,
        input_type: "document",
    };

    let response = client
        .post(VOYAGE_EMBED_URL)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .context("failed to reach Voyage AI API")?;

    parse_response(response, texts.len()).await
}

pub async fn embed_query_batch(
    texts: &[&str],
    model: &str,
    api_key: &str,
) -> Result<Vec<Vec<f32>>> {
    if texts.is_empty() {
        return Ok(Vec::new());
    }
    let client = build_client()?;
    let body = EmbedRequest {
        model,
        input: texts,
        input_type: "query",
    };
    let response = client
        .post(VOYAGE_EMBED_URL)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .context("failed to reach Voyage AI API")?;
    parse_response(response, texts.len()).await
}

fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .timeout(EMBED_TIMEOUT)
        .build()
        .context("failed to build HTTP client for embedding")
}

async fn embed_one(client: &Client, text: &str, model: &str, api_key: &str) -> Result<Vec<f32>> {
    let texts = [text];
    let body = EmbedRequest {
        model,
        input: &texts,
        input_type: "query",
    };

    let response = client
        .post(VOYAGE_EMBED_URL)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .context(
            "failed to reach Voyage AI API.\n\
             Check your internet connection and verify VOYAGE_API_KEY is set.",
        )?;

    let mut embeddings = parse_response(response, 1).await?;
    Ok(embeddings.swap_remove(0))
}

async fn parse_response(response: reqwest::Response, expected: usize) -> Result<Vec<Vec<f32>>> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!(
            "Voyage AI API returned HTTP {}: {}",
            status,
            body.chars().take(200).collect::<String>()
        );
    }

    let mut data: EmbedResponse = response
        .json()
        .await
        .context("failed to parse Voyage AI embedding response")?;

    if data.data.len() != expected {
        bail!(
            "Voyage AI returned {} embeddings, expected {}",
            data.data.len(),
            expected
        );
    }
    data.data.sort_unstable_by_key(|d| d.index);
    Ok(data.data.into_iter().map(|d| d.embedding).collect())
}
