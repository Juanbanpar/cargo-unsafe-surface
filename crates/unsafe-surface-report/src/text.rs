//! Human-readable text rendering.
//!
//! The layout follows the design in the project README: a summary header,
//! one section per finding with its reconstructed call path, then the
//! unreachable, structural, unresolved and diagnostics sections, and
//! finally the analysis limitations. All untrusted strings are
//! [`sanitize`]d.

use std::fmt::Write as _;

use unsafe_surface_core::{
    Confidence, DependencyOrigin, Reachability, ReportModel, Severity, UnsafeOpKind,
};

use crate::sanitize::sanitize;

/// Renders the report as human-readable text.
#[must_use]
pub fn render_text(report: &ReportModel) -> String {
    let mut out = String::new();
    header(&mut out, report);
    findings_section(&mut out, report);
    unreachable_section(&mut out, report);
    structural_section(&mut out, report);
    unresolved_section(&mut out, report);
    diagnostics_section(&mut out, report);
    limitations_section(&mut out, report);
    out
}

fn header(out: &mut String, report: &ReportModel) {
    let _ = writeln!(out, "Unsafe Surface Report");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Tool: {} {}",
        sanitize(&report.tool.name),
        sanitize(&report.tool.version)
    );
    let _ = writeln!(out, "Schema version: {}", report.schema_version);
    let _ = writeln!(out);
    let _ = writeln!(out, "Entry points:");
    if report.entry_points.is_empty() {
        let _ = writeln!(out, "  (none resolved)");
    }
    for entry in &report.entry_points {
        let _ = writeln!(out, "  {}", sanitize(&entry.item.to_string()));
    }
    let _ = writeln!(out);
    let s = &report.summary;
    let _ = writeln!(out, "Summary:");
    let _ = writeln!(
        out,
        "  Reachable unsafe operations: {}",
        s.reachable_unsafe_operations
    );
    let _ = writeln!(
        out,
        "  Reachable unsafe functions:  {}",
        s.reachable_unsafe_functions
    );
    let _ = writeln!(
        out,
        "  Reachable FFI calls:         {}",
        s.reachable_ffi_calls
    );
    let _ = writeln!(
        out,
        "  Manual Send/Sync impls:      {}",
        s.manual_send_sync_impls
    );
    let _ = writeln!(
        out,
        "  Inline assembly sites:       {}",
        s.inline_assembly_sites
    );
    let _ = writeln!(out, "  Transmutes:                  {}", s.transmutes);
    let _ = writeln!(
        out,
        "  Raw pointer dereferences:    {}",
        s.raw_pointer_dereferences
    );
    let _ = writeln!(
        out,
        "  Unreachable unsafe ops:      {}",
        s.unreachable_unsafe_operations
    );
    let _ = writeln!(out, "  Unresolved calls:            {}", s.unresolved_calls);
    let _ = writeln!(out);
}

fn findings_section(out: &mut String, report: &ReportModel) {
    let reachable: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.reachability == Reachability::Reachable)
        .collect();
    let _ = writeln!(
        out,
        "{}",
        count_line(
            "Findings (reachable)",
            report.summary.reachable_unsafe_operations,
            reachable.len()
        )
    );
    let _ = writeln!(out);
    for (index, finding) in reachable.iter().enumerate() {
        let op = &finding.operation;
        let _ = writeln!(out, "Finding {}", index + 1);
        let _ = writeln!(out, "  Kind:          {}", op.kind.label());
        let _ = writeln!(out, "  Confidence:    {}", confidence_label(op.confidence));
        let _ = writeln!(out, "  Justification: {}", op.justification.label());
        let _ = writeln!(
            out,
            "  Location:      {}",
            sanitize(&op.location.to_string())
        );
        let _ = writeln!(out, "  Package:       {}", package_label(finding));
        if let Some(detail) = &op.detail {
            let label = match op.kind {
                UnsafeOpKind::FfiCall | UnsafeOpKind::UnsafeFnCall => "  Target:        ",
                _ => "  Detail:        ",
            };
            let _ = writeln!(out, "{label}{}", sanitize(detail));
        }
        let _ = writeln!(
            out,
            "  Enclosing:     {}",
            sanitize(&finding.enclosing_item.to_string())
        );
        if let Some(path) = &finding.path {
            let _ = writeln!(out, "  Path:");
            for (i, step) in path.iter().enumerate() {
                let item = sanitize(&step.item.to_string());
                if i == 0 {
                    let _ = writeln!(out, "    {item}");
                } else {
                    // The call site belongs to the edge *into* this step,
                    // stored on the previous step.
                    let site = path[i - 1]
                        .call_site
                        .as_ref()
                        .map(|s| format!("  ({}:{})", sanitize(&s.file), s.line))
                        .unwrap_or_default();
                    let _ = writeln!(out, "    -> {item}{site}");
                }
            }
            // For FFI calls, the foreign symbol is the path terminus.
            if op.kind == UnsafeOpKind::FfiCall {
                if let Some(detail) = &op.detail {
                    if !path.is_empty() {
                        let _ = writeln!(out, "    -> {}", sanitize(detail));
                    }
                }
            }
        }
        let _ = writeln!(out);
    }
}

fn unreachable_section(out: &mut String, report: &ReportModel) {
    let unreachable: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.reachability == Reachability::Unreachable)
        .collect();
    let _ = writeln!(
        out,
        "{}",
        count_line(
            "Unreachable unsafe operations",
            report.summary.unreachable_unsafe_operations,
            unreachable.len()
        )
    );
    for finding in unreachable {
        let op = &finding.operation;
        let detail = op
            .detail
            .as_ref()
            .map(|d| format!(" — {}", sanitize(d)))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  {} — {} ({}){}",
            sanitize(&finding.enclosing_item.to_string()),
            op.kind.label(),
            sanitize(&op.location.to_string()),
            detail
        );
    }
    let _ = writeln!(out);
}

fn structural_section(out: &mut String, report: &ReportModel) {
    let _ = writeln!(
        out,
        "Structural findings: {}",
        report.structural_findings.len()
    );
    for finding in &report.structural_findings {
        let _ = writeln!(
            out,
            "  [{}] {} {} — {} ({}) — justification: {}",
            finding.kind.label(),
            sanitize(&finding.package.name),
            sanitize(finding.package.version.as_deref().unwrap_or("<unknown>")),
            sanitize(&finding.detail),
            sanitize(&finding.location.to_string()),
            finding.justification.label()
        );
    }
    let _ = writeln!(out);
}

fn unresolved_section(out: &mut String, report: &ReportModel) {
    let _ = writeln!(
        out,
        "{}",
        count_line(
            "Unresolved calls",
            report.unresolved_calls_total,
            report.unresolved_calls.len()
        )
    );
    for call in &report.unresolved_calls {
        let _ = writeln!(
            out,
            "  {} -> {} ({}) — {}",
            sanitize(&call.caller.to_string()),
            sanitize(&call.callee_text),
            sanitize(&call.location.to_string()),
            call.reason.label()
        );
    }
    let _ = writeln!(out);
}

fn diagnostics_section(out: &mut String, report: &ReportModel) {
    if report.diagnostics.is_empty() {
        return;
    }
    let _ = writeln!(out, "Diagnostics: {}", report.diagnostics.len());
    for diagnostic in &report.diagnostics {
        let severity = match diagnostic.severity {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        let location = diagnostic
            .location
            .as_ref()
            .map(|l| format!(" ({})", sanitize(&l.to_string())))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  [{severity}] {}{location}",
            sanitize(&diagnostic.message)
        );
    }
    let _ = writeln!(out);
}

fn limitations_section(out: &mut String, report: &ReportModel) {
    let _ = writeln!(out, "Analysis limitations:");
    for limitation in &report.limitations {
        let _ = writeln!(out, "  - {}", sanitize(limitation));
    }
}

/// Section header showing the complete count, plus the listed count when
/// the section's list is capped below it (summary counts are always
/// complete; see `docs/json-schema.md`).
fn count_line(what: &str, total: u64, listed: usize) -> String {
    if u64::try_from(listed).unwrap_or(u64::MAX) == total {
        format!("{what}: {total}")
    } else {
        format!("{what}: {total} (listed: {listed})")
    }
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Confirmed => "confirmed",
        Confidence::Inferred => "inferred",
    }
}

fn package_label(finding: &unsafe_surface_core::Finding) -> String {
    let origin = match finding.package.origin {
        DependencyOrigin::Workspace => "workspace",
        DependencyOrigin::Path => "path",
        DependencyOrigin::Registry => "registry",
        DependencyOrigin::Git => "git",
        DependencyOrigin::Unknown => "unknown",
    };
    sanitize(&format!(
        "{} {} ({origin})",
        finding.package.name,
        finding.package.version.as_deref().unwrap_or("<unknown>")
    ))
}
