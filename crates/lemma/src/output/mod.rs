pub mod gaps;
pub mod patch;
pub mod qedspec;
pub mod report;

use anyhow::Result;
use std::path::Path;

use crate::{cli::OutputFormat, types::AnalysisResult};

#[derive(Debug, Default)]
pub struct ArtifactSet {
    pub qedspec: bool,
    pub markdown_report: bool,
}

pub fn write_all(
    result: &AnalysisResult,
    format: OutputFormat,
    output_path: Option<&Path>,
    artifacts: &ArtifactSet,
) -> Result<()> {
    match format {
        OutputFormat::Text => {
            if let Some(path) = output_path {
                let mut file = std::fs::File::create(path)
                    .map_err(|e| anyhow::anyhow!("failed to create output file: {}", e))?;
                gaps::write_text_report(result, &mut file)?;
            } else {
                gaps::write_text_report(result, &mut std::io::stdout())?;
            }
        }
        OutputFormat::Json => {
            if let Some(path) = output_path {
                let mut file = std::fs::File::create(path)
                    .map_err(|e| anyhow::anyhow!("failed to create output file: {}", e))?;
                gaps::write_json_report(result, &mut file)
                    .map_err(|e| anyhow::anyhow!("JSON serialisation failed: {}", e))?;
            } else {
                gaps::write_json_report(result, &mut std::io::stdout())
                    .map_err(|e| anyhow::anyhow!("JSON serialisation failed: {}", e))?;
            }
        }
    }

    if artifacts.qedspec && !result.invariants.is_empty() {
        let spec_path = derive_artifact_path(result, "qedspec");
        let content = qedspec::generate(result.program.as_ref(), None, &result.invariants);
        qedspec::write_to_file(&spec_path, &content)?;
        eprintln!("  Wrote QEDSpec: {}", spec_path.display());
    }

    if artifacts.markdown_report {
        let report_path = derive_artifact_path(result, "md");
        let content = report::generate_markdown(result);
        report::write_to_file(&report_path, &content)?;
        eprintln!("  Wrote report: {}", report_path.display());
    }

    Ok(())
}

fn derive_artifact_path(result: &AnalysisResult, extension: &str) -> std::path::PathBuf {
    let base = result
        .program
        .as_ref()
        .replace(['/', '\\', ' '], "_")
        .to_ascii_lowercase();

    let stem = if extension == "md" {
        format!("{}_security_report", base)
    } else {
        base
    };

    std::path::PathBuf::from(format!("{}.{}", stem, extension))
}
