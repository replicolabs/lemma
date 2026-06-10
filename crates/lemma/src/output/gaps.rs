use owo_colors::OwoColorize;
use std::io::Write;

use crate::types::{AnalysisResult, SecurityGap, Severity};

pub fn write_text_report<W: Write>(
    result: &AnalysisResult,
    writer: &mut W,
) -> std::io::Result<()> {
    write_score_banner(result, writer)?;
    write_summary(result, writer)?;
    write_gaps(result, writer)?;
    write_acknowledged(result, writer)?;
    Ok(())
}

fn write_score_banner<W: Write>(result: &AnalysisResult, w: &mut W) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "  {} {}",
        "Lemma Security Analysis".bold(),
        format!("v{}", result.lemma_version).dimmed(),
    )?;
    writeln!(w, "  {} {}", "Program:".dimmed(), result.program.bold())?;
    writeln!(
        w,
        "  {} {} / {}",
        "Framework:".dimmed(),
        result.framework.as_str(),
        result.program_type.as_str(),
    )?;
    writeln!(
        w,
        "  {} {}",
        "KB version:".dimmed(),
        result.kb_version,
    )?;
    writeln!(w)?;

    Ok(())
}

fn write_summary<W: Write>(result: &AnalysisResult, w: &mut W) -> std::io::Result<()> {
    let unacked: Vec<&SecurityGap> = result
        .gaps
        .iter()
        .filter(|g| !g.acknowledged)
        .collect();

    let counts = severity_counts(&unacked);

    writeln!(w, "  {} gap(s) found:", unacked.len().bold())?;

    if counts.critical > 0 {
        writeln!(w, "    {} critical", format!("{}", counts.critical).red().bold())?;
    }
    if counts.high > 0 {
        writeln!(w, "    {} high", format!("{}", counts.high).truecolor(255, 100, 0).bold())?;
    }
    if counts.medium > 0 {
        writeln!(w, "    {} medium", format!("{}", counts.medium).yellow())?;
    }
    if counts.low > 0 {
        writeln!(w, "    {} low", format!("{}", counts.low).blue())?;
    }
    if counts.info > 0 {
        writeln!(w, "    {} informational", format!("{}", counts.info).dimmed())?;
    }

    let acked_count = result.gaps.iter().filter(|g| g.acknowledged).count();
    if acked_count > 0 {
        writeln!(w, "    {} acknowledged (excluded from score)", acked_count.to_string().dimmed())?;
    }
    writeln!(w)?;

    Ok(())
}

fn write_gaps<W: Write>(result: &AnalysisResult, w: &mut W) -> std::io::Result<()> {
    let unacked: Vec<&SecurityGap> = result
        .gaps
        .iter()
        .filter(|g| !g.acknowledged)
        .collect();

    if unacked.is_empty() {
        writeln!(w, "  {} No active security gaps found.", "✓".green().bold())?;
        writeln!(w)?;
        return Ok(());
    }

    writeln!(w, "  {}", "━".repeat(60).dimmed())?;
    writeln!(w)?;

    for gap in &unacked {
        write_gap(gap, w)?;
    }

    Ok(())
}

fn write_gap<W: Write>(gap: &SecurityGap, w: &mut W) -> std::io::Result<()> {
    let badge = severity_badge(gap.severity);
    let source_label_text = format!("[{}]", gap.source);
    let source_label = source_label_text.dimmed();

    writeln!(
        w,
        "  {} {} {} {}",
        badge,
        gap.id.bold(),
        gap.handler_name.cyan(),
        source_label,
    )?;
    writeln!(w, "  {}", gap.description)?;
    writeln!(
        w,
        "  {} {}",
        "Rule/Finding:".dimmed(),
        gap.source_rule_id,
    )?;
    writeln!(w)?;

    Ok(())
}

fn write_acknowledged<W: Write>(result: &AnalysisResult, w: &mut W) -> std::io::Result<()> {
    let acked: Vec<&SecurityGap> = result
        .gaps
        .iter()
        .filter(|g| g.acknowledged)
        .collect();

    if acked.is_empty() {
        return Ok(());
    }

    writeln!(w, "  {}", "Acknowledged gaps:".dimmed())?;
    for gap in acked {
        let reason = gap.ack_reason.as_deref().unwrap_or("no reason given");
        writeln!(
            w,
            "  {} {} — {}",
            "✓".dimmed(),
            gap.id.dimmed(),
            reason.dimmed(),
        )?;
    }
    writeln!(w)?;

    Ok(())
}

pub fn write_json_report<W: Write>(
    result: &AnalysisResult,
    writer: &mut W,
) -> Result<(), serde_json::Error> {
    serde_json::to_writer_pretty(writer, result)
}

struct SeverityCounts {
    critical: usize,
    high:     usize,
    medium:   usize,
    low:      usize,
    info:     usize,
}

fn severity_counts(gaps: &[&SecurityGap]) -> SeverityCounts {
    let mut c = SeverityCounts { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for gap in gaps {
        match gap.severity {
            Severity::Critical      => c.critical += 1,
            Severity::High          => c.high     += 1,
            Severity::Medium        => c.medium   += 1,
            Severity::Low           => c.low      += 1,
            Severity::Informational => c.info     += 1,
        }
    }
    c
}

fn severity_badge(severity: Severity) -> String {
    match severity {
        Severity::Critical      => "[CRITICAL]".red().bold().to_string(),
        Severity::High          => "[HIGH]    ".truecolor(255, 100, 0).bold().to_string(),
        Severity::Medium        => "[MEDIUM]  ".yellow().to_string(),
        Severity::Low           => "[LOW]     ".blue().to_string(),
        Severity::Informational => "[INFO]    ".dimmed().to_string(),
    }
}