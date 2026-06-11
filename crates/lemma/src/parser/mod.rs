pub mod anchor;
pub mod native;
pub mod pinocchio;
pub mod quasar;

use crate::types::{Framework, InstructionHandler};
use anyhow::{Context, Result};
use std::path::Path;

pub trait Parser {
    fn parse(&self, source: &str, source_path: &str) -> Vec<InstructionHandler>;
}

pub fn detect_framework(program_dir: &Path) -> Option<Framework> {
    let cargo_toml_path = program_dir.join("Cargo.toml");
    let contents = std::fs::read_to_string(&cargo_toml_path).ok()?;
    let lower = contents.to_ascii_lowercase();

    if lower.contains("pinocchio") {
        return Some(Framework::Pinocchio);
    }
    if lower.contains("quasar-lang") || lower.contains("quasar_lang") {
        return Some(Framework::Quasar);
    }
    if lower.contains("anchor-lang") || lower.contains("anchor_lang") {
        return Some(Framework::Anchor);
    }
    if lower.contains("solana-program") || lower.contains("solana_program") {
        return Some(Framework::Native);
    }

    None
}

pub fn load_source(path: &Path) -> Result<(String, String)> {
    if path.is_file() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read source file {}", path.display()))?;
        let label = path.display().to_string();
        return Ok((text, label));
    }

    if path.is_dir() {
        return load_source_dir(path);
    }

    anyhow::bail!(
        "path {} does not exist or is not a file or directory",
        path.display()
    );
}

fn load_source_dir(dir: &Path) -> Result<(String, String)> {
    let mut rs_files: Vec<std::path::PathBuf> = Vec::new();
    collect_rs_files(dir, &mut rs_files);

    if rs_files.is_empty() {
        anyhow::bail!("no .rs files found under {}", dir.display());
    }

    rs_files.sort();

    let mut buf = String::new();
    for file_path in &rs_files {
        let relative = file_path.strip_prefix(dir).unwrap_or(file_path.as_path());

        buf.push_str("// FILE: ");
        buf.push_str(&relative.display().to_string());
        buf.push('\n');

        let contents = std::fs::read_to_string(file_path)
            .with_context(|| format!("failed to read {}", file_path.display()))?;
        buf.push_str(&contents);
        buf.push('\n');
    }

    let label = format!("{} ({} files)", dir.display(), rs_files.len());
    Ok((buf, label))
}

fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

pub fn parse(source: &str, source_label: &str, framework: Framework) -> Vec<InstructionHandler> {
    match framework {
        Framework::Anchor => anchor::AnchorParser.parse(source, source_label),
        Framework::Quasar => quasar::QuasarParser.parse(source, source_label),
        Framework::Pinocchio => pinocchio::PinocchioParser.parse(source, source_label),
        Framework::Native => native::NativeParser.parse(source, source_label),
    }
}

pub(crate) fn gather_signature(lines: &[&str], start: usize) -> String {
    let mut sig = String::new();
    for line in lines.iter().skip(start).take(20) {
        sig.push_str(line.trim());
        sig.push(' ');
        if line.contains('{') || line.trim_end().ends_with(';') {
            break;
        }
    }
    sig
}
