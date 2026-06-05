use anyhow::{Context, Result};
use std::path::Path;

pub fn display_diff(diff: &str) {
    use owo_colors::OwoColorize;

    for line in diff.lines() {
        if line.starts_with("---") || line.starts_with("+++") {
            println!("{}", line.bold());
        } else if line.starts_with("@@") {
            println!("{}", line.cyan());
        } else if line.starts_with('+') {
            println!("{}", line.green());
        } else if line.starts_with('-') {
            println!("{}", line.red());
        } else {
            println!("{}", line.dimmed());
        }
    }
}

pub fn apply_to_file(path: &Path, diff: &str) -> Result<()> {
    let original = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let patched = apply_unified_diff(&original, diff)
        .with_context(|| format!("failed to apply patch to {}", path.display()))?;

    std::fs::write(path, &patched)
        .with_context(|| format!("failed to write patched file to {}", path.display()))?;

    Ok(())
}

pub fn apply_unified_diff(source: &str, diff: &str) -> Result<String> {
    let source_lines: Vec<&str> = source.lines().collect();
    let mut result: Vec<&str>   = Vec::with_capacity(source_lines.len() + 16);
    let mut source_pos = 0usize;

    for hunk in parse_hunks(diff) {
        let hunk_start = hunk.orig_start.saturating_sub(1);
        while source_pos < hunk_start {
            if source_pos < source_lines.len() {
                result.push(source_lines[source_pos]);
            }
            source_pos += 1;
        }

        for change in &hunk.changes {
            match change.kind {
                ChangeKind::Context => {
                    if source_pos < source_lines.len() {
                        let src_line = source_lines[source_pos].trim_end();
                        let ctx_line = change.text.trim_end();
                        if src_line != ctx_line {
                            anyhow::bail!(
                                "patch context mismatch at line {}: \
                                 expected {:?}, found {:?}",
                                source_pos + 1,
                                ctx_line,
                                src_line,
                            );
                        }
                        result.push(source_lines[source_pos]);
                    }
                    source_pos += 1;
                }
                ChangeKind::Remove => {
                    source_pos += 1;
                }
                ChangeKind::Add => {
                    result.push(change.text);
                }
            }
        }
    }

    while source_pos < source_lines.len() {
        result.push(source_lines[source_pos]);
        source_pos += 1;
    }

    Ok(result.join("\n"))
}

#[derive(Debug)]
struct Hunk<'a> {
    orig_start: usize,
    changes:    Vec<Change<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChangeKind { Context, Add, Remove }

#[derive(Debug)]
struct Change<'a> {
    kind: ChangeKind,
    text: &'a str,
}

fn parse_hunks(diff: &str) -> Vec<Hunk<'_>> {
    let mut hunks: Vec<Hunk<'_>> = Vec::new();
    let mut current: Option<Hunk<'_>> = None;

    for line in diff.lines() {
        if line.starts_with("@@") {
            if let Some(h) = current.take() {
                hunks.push(h);
            }
            let orig_start = parse_hunk_header(line).unwrap_or(1);
            current = Some(Hunk { orig_start, changes: Vec::new() });
        } else if let Some(ref mut hunk) = current {
            if let Some(text) = line.strip_prefix('+') {
                hunk.changes.push(Change { kind: ChangeKind::Add, text });
            } else if let Some(text) = line.strip_prefix('-') {
                hunk.changes.push(Change { kind: ChangeKind::Remove, text });
            } else if let Some(text) = line.strip_prefix(' ') {
                hunk.changes.push(Change { kind: ChangeKind::Context, text });
            }
        }
    }

    if let Some(h) = current {
        hunks.push(h);
    }

    hunks
}

fn parse_hunk_header(line: &str) -> Option<usize> {
    let inner = line.trim_start_matches("@@").trim();
    let minus = inner.strip_prefix('-')?;
    let num_str = minus.split([',', ' ']).next()?;
    num_str.parse().ok()
}