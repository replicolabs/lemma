use crate::types::{KnowledgeBase, RetrievedEntry};

pub fn search(
    kb:              &KnowledgeBase,
    query_embedding: &[f32],
    top_k:           usize,
    min_similarity:  f32,
) -> Vec<RetrievedEntry> {
    if kb.entries.is_empty() || top_k == 0 {
        return Vec::new();
    }

    let query_dims = query_embedding.len();
    debug_assert_eq!(
        query_dims,
        kb.embedding_dimensions as usize,
        "query embedding dimensions {} do not match KB dimensions {}",
        query_dims,
        kb.embedding_dimensions,
    );
    let mut scores: Vec<(f32, usize)> = kb
        .entries
        .iter()
        .enumerate()
        .filter_map(|(idx, entry)| {
            if entry.embedding.len() != query_dims {
                return None;
            }
            let score = cosine_similarity(query_embedding, &entry.embedding);
            if score >= min_similarity {
                Some((score, idx))
            } else {
                None
            }
        })
        .collect();

    if scores.is_empty() {
        return Vec::new();
    }
    let k = top_k.min(scores.len());
    if k < scores.len() {
        scores.select_nth_unstable_by(k - 1, |(a, _), (b, _)| {
            b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal)
        });
        scores.truncate(k);
    }

    scores.sort_unstable_by(|(a, _), (b, _)| {
        b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal)
    });

    scores
        .into_iter()
        .map(|(score, idx)| RetrievedEntry {
            entry: kb.entries[idx].clone(),
            score,
        })
        .collect()
}

#[inline]
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());

    let mut dot  = 0.0f32;
    let mut mag_a = 0.0f32;
    let mut mag_b = 0.0f32;

    for (&ai, &bi) in a.iter().zip(b.iter()) {
        dot   += ai * bi;
        mag_a += ai * ai;
        mag_b += bi * bi;
    }

    let denom = mag_a.sqrt() * mag_b.sqrt();
    if denom < f32::EPSILON {
        0.0
    } else {
        (dot / denom).clamp(-1.0, 1.0)
    }
}

pub fn filter_by_vuln_class<'a>(
    entries:    &'a [RetrievedEntry],
    vuln_class: &str,
) -> impl Iterator<Item = &'a RetrievedEntry> {
    entries.iter().filter(move |e| {
        e.entry
            .vulnerability_class
            .as_deref()
            .map(|vc| vc == vuln_class)
            .unwrap_or(false)
    })
}

pub fn deduplicate(entries: Vec<RetrievedEntry>) -> Vec<RetrievedEntry> {
    let mut seen = std::collections::HashSet::with_capacity(entries.len());
    entries
        .into_iter()
        .filter(|e| seen.insert(e.entry.id.clone()))
        .collect()
}