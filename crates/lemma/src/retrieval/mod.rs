pub mod embed;
pub mod search;

use anyhow::Result;

use crate::{
    config::Config,
    types::{InstructionHandler, KnowledgeBase, ProgramType, RetrievedEntry},
};

const ALL_VULN_CLASSES: &[&str] = &[
    "missing_signer_check",
    "missing_ownership_check",
    "arithmetic_error",
    "insecure_initialisation",
    "oracle_validation",
    "arbitrary_cpi",
    "lifecycle_violation",
    "permissionless_state_write",
    "init_without_pda",
    "stored_field_never_written",
    "paired_validator_mismatch",
    "authority_not_revoked_on_close",
];

pub async fn retrieve(
    handler:      &InstructionHandler,
    program_type: ProgramType,
    kb:           &KnowledgeBase,
    config:       &Config,
    top_k:        usize,
    min_sim:      f32,
) -> Result<Vec<RetrievedEntry>> {
    let api_key = config
        .voyage_api_key()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Voyage API key not set.\n\
                 Run `lemma init` to configure it, or set VOYAGE_API_KEY."
            )
        })?;

    let model = kb.embedding_model.as_ref();
    let query_text = build_query_text(handler, program_type);
    let query_embedding = embed::embed_query(&query_text, model, api_key).await?;
    let pass1 = search::search(kb, &query_embedding, top_k, min_sim);
    let covered_classes: std::collections::HashSet<&str> = pass1
        .iter()
        .filter_map(|e| e.entry.vulnerability_class.as_deref())
        .collect();
    let mut pass2: Vec<RetrievedEntry> = Vec::new();
    for &vuln_class in ALL_VULN_CLASSES {
        if covered_classes.contains(vuln_class) {
            continue;
        }
        let class_query = format!(
            "Program type: {}\nInstruction: {}\nVulnerability: {}",
            program_type.as_str(),
            handler.name.as_ref(),
            vuln_class.replace('_', " "),
        );

        let class_embedding = embed::embed_query(&class_query, model, api_key).await?;
        let mut class_results = search::search(kb, &class_embedding, 3, min_sim);
        class_results.retain(|e| {
            search::filter_by_vuln_class(
                std::slice::from_ref(e),
                vuln_class,
            )
            .next()
            .is_some()
        });

        pass2.extend(class_results);
    }
    let mut merged = pass1;
    merged.extend(pass2);
    Ok(search::deduplicate(merged))
}

fn build_query_text(handler: &InstructionHandler, program_type: ProgramType) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(6);

    parts.push(format!("Program type: {}", program_type.as_str()));
    parts.push(format!("Instruction: {}", handler.name.as_ref()));

    let account_names: Vec<&str> = handler
        .accounts
        .iter()
        .map(|a| a.name.as_ref())
        .collect();
    if !account_names.is_empty() {
        parts.push(format!("Accounts: {}", account_names.join(", ")));
    }
    let unchecked: Vec<&str> = handler
        .unchecked_accounts()
        .map(|a| a.name.as_ref())
        .collect();
    if !unchecked.is_empty() {
        parts.push(format!("Unchecked accounts: {}", unchecked.join(", ")));
    }

    if !handler.cpi_calls.is_empty() {
        parts.push(format!("CPI calls: {}", handler.cpi_calls.len()));
        let unverified = handler
            .cpi_calls
            .iter()
            .filter(|c| !c.program_verified)
            .count();
        if unverified > 0 {
            parts.push(format!("Unverified CPI targets: {}", unverified));
        }
    }

    let token_arithmetic = handler
        .arithmetic
        .iter()
        .filter(|op| {
            let lhs = op.lhs.to_ascii_lowercase();
            let rhs = op.rhs.to_ascii_lowercase();
            ["amount", "balance", "fee", "collateral", "reserve", "debt"]
                .iter()
                .any(|kw| lhs.contains(kw) || rhs.contains(kw))
        })
        .count();
    if token_arithmetic > 0 {
        parts.push(format!("Token arithmetic operations: {}", token_arithmetic));
    }

    parts.join("\n")
}