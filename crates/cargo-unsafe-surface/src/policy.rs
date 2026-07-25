//! Policy evaluation.
//!
//! A policy file (`--policy policy.toml`) encodes organisational rules
//! over analysis results. Evaluation distinguishes four outcomes:
//!
//! * **configuration errors** — malformed files or unknown keys (loading
//!   fails, exit code 1);
//! * **policy violations** — a rule denies something the analysis found
//!   (exit code 2);
//! * **uncertainty violations** — unresolved calls exceed the configured
//!   tolerance; these are violations too, but reported distinctly because
//!   they reflect *analysis uncertainty*, not confirmed unsafe code;
//! * **pass** — everything within tolerance.
//!
//! Unresolved calls are never treated as safe: `fail_on_unresolved_calls`
//! and `maximum_unresolved_calls` exist precisely to let strict
//! environments fail on uncertainty.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use unsafe_surface_core::{
    DependencyOrigin, Reachability, ReportModel, SafetyJustification, UnsafeOpKind,
};

/// A loaded policy file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Core rules.
    #[serde(default)]
    pub policy: PolicyRules,
    /// Dependency-oriented rules.
    #[serde(default)]
    pub dependencies: DependencyRules,
}

/// Core policy rules (`[policy]` section).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyRules {
    /// Fail on any reachable `asm!`/`global_asm!`/`naked_asm!`.
    pub deny_reachable_inline_assembly: bool,
    /// Fail on reachable accesses to `static mut`.
    pub deny_reachable_mutable_statics: bool,
    /// Fail on reachable `transmute`/`transmute_copy`.
    pub deny_reachable_transmutes: bool,
    /// Fail on any reachable unsafe operation (strict mode).
    pub deny_reachable_unsafe_code: bool,
    /// Maximum tolerated reachable FFI calls.
    pub maximum_reachable_ffi_calls: Option<u64>,
    /// Maximum tolerated reachable unsafe operations.
    pub maximum_reachable_unsafe_operations: Option<u64>,
    /// Maximum tolerated unresolved calls (uncertainty budget).
    pub maximum_unresolved_calls: Option<u64>,
    /// Every reachable unsafe operation must carry a `SAFETY:` comment.
    pub require_safety_comments: bool,
    /// Fail when any non-std call is unresolved (strict uncertainty mode).
    pub fail_on_unresolved_calls: bool,
}

/// Dependency rules (`[dependencies]` section).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DependencyRules {
    /// Packages that must not appear in the analysis universe at all.
    pub deny: Vec<String>,
    /// The only third-party packages allowed to contribute reachable
    /// unsafe code. When non-empty, reachable unsafe findings from any
    /// other third-party package are violations.
    pub allow_unsafe: Vec<String>,
}

/// One violated rule.
#[derive(Debug, Clone)]
pub struct PolicyViolation {
    /// Rule name (TOML key).
    pub rule: String,
    /// Human-readable explanation.
    pub message: String,
    /// Whether the violation reflects analysis uncertainty rather than a
    /// confirmed finding.
    pub uncertainty: bool,
}

/// The outcome of evaluating a policy.
#[derive(Debug, Default)]
pub struct PolicyEvaluation {
    /// All violations, deterministically ordered.
    pub violations: Vec<PolicyViolation>,
}

impl PolicyEvaluation {
    /// Whether any rule was violated.
    #[must_use]
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Prints a human-readable summary to stderr.
    pub fn print_summary(&self) {
        if self.violations.is_empty() {
            eprintln!("policy: OK (no violations)");
            return;
        }
        eprintln!("policy: {} violation(s)", self.violations.len());
        for violation in &self.violations {
            let marker = if violation.uncertainty {
                " [uncertainty]"
            } else {
                ""
            };
            eprintln!("  - [{}]{} {}", violation.rule, marker, violation.message);
        }
    }
}

impl Policy {
    /// Loads and parses a policy file. Unknown keys are configuration
    /// errors, not silently ignored.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read policy file {}", path.display()))?;
        let policy: Policy = toml::from_str(&text)
            .with_context(|| format!("invalid policy file {}", path.display()))?;
        Ok(policy)
    }

    /// Evaluates the policy against a finished report.
    #[must_use]
    pub fn evaluate(&self, report: &ReportModel) -> PolicyEvaluation {
        let mut evaluation = PolicyEvaluation::default();
        let rules = &self.policy;

        let reachable = || {
            report
                .findings
                .iter()
                .filter(|f| f.reachability == Reachability::Reachable)
        };

        // Deny-by-kind rules (one violation per finding keeps locations
        // actionable).
        let deny_rules = [
            (
                rules.deny_reachable_inline_assembly,
                UnsafeOpKind::InlineAssembly,
                "deny_reachable_inline_assembly",
            ),
            (
                rules.deny_reachable_mutable_statics,
                UnsafeOpKind::MutableStaticAccess,
                "deny_reachable_mutable_statics",
            ),
            (
                rules.deny_reachable_transmutes,
                UnsafeOpKind::Transmute,
                "deny_reachable_transmutes",
            ),
        ];
        for (enabled, kind, rule) in deny_rules {
            if !enabled {
                continue;
            }
            for finding in reachable().filter(|f| f.operation.kind == kind) {
                evaluation.violations.push(PolicyViolation {
                    rule: rule.to_owned(),
                    message: format!(
                        "reachable {} at {} in {}",
                        kind.label(),
                        finding.operation.location,
                        finding.enclosing_item
                    ),
                    uncertainty: false,
                });
            }
        }

        if rules.deny_reachable_unsafe_code && report.summary.reachable_unsafe_operations > 0 {
            evaluation.violations.push(PolicyViolation {
                rule: "deny_reachable_unsafe_code".to_owned(),
                message: format!(
                    "{} reachable unsafe operation(s) found",
                    report.summary.reachable_unsafe_operations
                ),
                uncertainty: false,
            });
        }

        // Threshold rules.
        let thresholds = [
            (
                rules.maximum_reachable_ffi_calls,
                report.summary.reachable_ffi_calls,
                "maximum_reachable_ffi_calls",
                "reachable FFI calls",
            ),
            (
                rules.maximum_reachable_unsafe_operations,
                report.summary.reachable_unsafe_operations,
                "maximum_reachable_unsafe_operations",
                "reachable unsafe operations",
            ),
        ];
        for (maximum, actual, rule, what) in thresholds {
            if let Some(maximum) = maximum {
                if actual > maximum {
                    evaluation.violations.push(PolicyViolation {
                        rule: rule.to_owned(),
                        message: format!("{actual} {what} exceed the maximum of {maximum}"),
                        uncertainty: false,
                    });
                }
            }
        }

        if rules.require_safety_comments {
            for finding in
                reachable().filter(|f| f.operation.justification == SafetyJustification::Absent)
            {
                evaluation.violations.push(PolicyViolation {
                    rule: "require_safety_comments".to_owned(),
                    message: format!(
                        "reachable {} without a SAFETY: comment at {} in {}",
                        finding.operation.kind.label(),
                        finding.operation.location,
                        finding.enclosing_item
                    ),
                    uncertainty: false,
                });
            }
        }

        // Uncertainty rules.
        if rules.fail_on_unresolved_calls && report.unresolved_calls_total > 0 {
            evaluation.violations.push(PolicyViolation {
                rule: "fail_on_unresolved_calls".to_owned(),
                message: format!(
                    "{} call site(s) could not be resolved",
                    report.unresolved_calls_total
                ),
                uncertainty: true,
            });
        }
        if let Some(maximum) = rules.maximum_unresolved_calls {
            if report.unresolved_calls_total > maximum {
                evaluation.violations.push(PolicyViolation {
                    rule: "maximum_unresolved_calls".to_owned(),
                    message: format!(
                        "{} unresolved calls exceed the maximum of {maximum}",
                        report.unresolved_calls_total
                    ),
                    uncertainty: true,
                });
            }
        }

        // Dependency rules.
        for denied in &self.dependencies.deny {
            if let Some(package) = report.packages.iter().find(|p| p.id.name == *denied) {
                evaluation.violations.push(PolicyViolation {
                    rule: "dependencies.deny".to_owned(),
                    message: format!(
                        "denied package {} is present in the analysis universe",
                        package.id
                    ),
                    uncertainty: false,
                });
            }
        }
        if !self.dependencies.allow_unsafe.is_empty() {
            let third_party = |origin: DependencyOrigin| {
                matches!(
                    origin,
                    DependencyOrigin::Registry | DependencyOrigin::Git | DependencyOrigin::Path
                )
            };
            let mut offenders: Vec<String> = reachable()
                .filter(|f| third_party(f.package.origin))
                .filter(|f| !self.dependencies.allow_unsafe.contains(&f.package.name))
                .map(|f| f.package.to_string())
                .collect();
            offenders.sort();
            offenders.dedup();
            for offender in offenders {
                evaluation.violations.push(PolicyViolation {
                    rule: "dependencies.allow_unsafe".to_owned(),
                    message: format!(
                        "third-party package {offender} contributes reachable unsafe code \
                         but is not in allow_unsafe"
                    ),
                    uncertainty: false,
                });
            }
        }

        evaluation.violations.sort_by(|a, b| {
            (&a.rule, a.uncertainty, &a.message).cmp(&(&b.rule, b.uncertainty, &b.message))
        });
        evaluation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unsafe_surface_core::*;

    fn policy(toml_text: &str) -> Policy {
        toml::from_str(toml_text).expect("test policy must parse")
    }

    fn report_with(findings: Vec<UnsafeOpKind>, unresolved: u64) -> ReportModel {
        let package = PackageId::new("demo", Some("0.1.0".into()), DependencyOrigin::Workspace);
        ReportModel {
            schema_version: SCHEMA_VERSION,
            tool: ToolInfo {
                name: "cargo-unsafe-surface".into(),
                version: "0.1.0".into(),
            },
            configuration: AnalysisConfiguration::default(),
            packages: vec![PackageInfo {
                id: package.clone(),
                root: "demo".into(),
                sources_available: true,
            }],
            entry_points: vec![],
            summary: SummaryCounts {
                reachable_unsafe_operations: findings.len() as u64,
                reachable_ffi_calls: findings
                    .iter()
                    .filter(|k| **k == UnsafeOpKind::FfiCall)
                    .count() as u64,
                unresolved_calls: unresolved,
                ..SummaryCounts::default()
            },
            findings: findings
                .iter()
                .enumerate()
                .map(|(i, kind)| Finding {
                    id: i as u64,
                    operation: UnsafeOperation::new(
                        *kind,
                        SourceLocation::new("demo/src/lib.rs", 1 + i as u32, 1),
                    ),
                    enclosing_item: ItemPath::parse("demo::f").unwrap(),
                    package: package.clone(),
                    reachability: Reachability::Reachable,
                    path: Some(vec![]),
                })
                .collect(),
            structural_findings: vec![],
            unresolved_calls: vec![],
            unresolved_calls_total: unresolved,
            diagnostics: vec![],
            limitations: vec![],
        }
    }

    #[test]
    fn empty_policy_never_violates() {
        let evaluation = policy("").evaluate(&report_with(
            vec![UnsafeOpKind::InlineAssembly, UnsafeOpKind::FfiCall],
            5,
        ));
        assert!(!evaluation.has_violations());
    }

    #[test]
    fn deny_rules_fire_per_finding() {
        let p = policy("[policy]\ndeny_reachable_inline_assembly = true\n");
        let evaluation = p.evaluate(&report_with(
            vec![
                UnsafeOpKind::InlineAssembly,
                UnsafeOpKind::InlineAssembly,
                UnsafeOpKind::FfiCall,
            ],
            0,
        ));
        assert_eq!(evaluation.violations.len(), 2);
        assert!(evaluation
            .violations
            .iter()
            .all(|v| v.rule == "deny_reachable_inline_assembly"));
    }

    #[test]
    fn threshold_rules() {
        let p = policy("[policy]\nmaximum_reachable_ffi_calls = 1\n");
        let evaluation = p.evaluate(&report_with(
            vec![UnsafeOpKind::FfiCall, UnsafeOpKind::FfiCall],
            0,
        ));
        assert_eq!(evaluation.violations.len(), 1);
        assert!(evaluation.violations[0]
            .message
            .contains("2 reachable FFI calls"));
    }

    #[test]
    fn uncertainty_rules_are_marked() {
        let p = policy("[policy]\nfail_on_unresolved_calls = true\n");
        let evaluation = p.evaluate(&report_with(vec![], 3));
        assert_eq!(evaluation.violations.len(), 1);
        assert!(evaluation.violations[0].uncertainty);

        let p = policy("[policy]\nmaximum_unresolved_calls = 2\n");
        assert!(p.evaluate(&report_with(vec![], 1)).violations.is_empty());
        assert_eq!(p.evaluate(&report_with(vec![], 3)).violations.len(), 1);
    }

    #[test]
    fn safety_comment_rule() {
        let p = policy("[policy]\nrequire_safety_comments = true\n");
        let evaluation = p.evaluate(&report_with(vec![UnsafeOpKind::UnsafeBlock], 0));
        assert_eq!(evaluation.violations.len(), 1);
        assert!(evaluation.violations[0]
            .message
            .contains("without a SAFETY: comment"));
    }

    #[test]
    fn dependency_deny_rule() {
        let p = policy("[dependencies]\ndeny = [\"demo\"]\n");
        let evaluation = p.evaluate(&report_with(vec![], 0));
        assert_eq!(evaluation.violations.len(), 1);
        assert!(evaluation.violations[0].message.contains("demo"));
    }

    #[test]
    fn allow_unsafe_only_flags_third_party_packages() {
        let p = policy("[dependencies]\nallow_unsafe = [\"libc\"]\n");
        // Workspace findings are first-party: never flagged.
        assert!(p
            .evaluate(&report_with(vec![UnsafeOpKind::UnsafeBlock], 0))
            .violations
            .is_empty());

        // A registry package not in the list is flagged.
        let mut report = report_with(vec![UnsafeOpKind::UnsafeBlock], 0);
        report.findings[0].package =
            PackageId::new("socket2", Some("0.5.8".into()), DependencyOrigin::Registry);
        let evaluation = p.evaluate(&report);
        assert_eq!(evaluation.violations.len(), 1);
        assert!(evaluation.violations[0].message.contains("socket2"));

        // …but not when listed.
        let p = policy("[dependencies]\nallow_unsafe = [\"libc\", \"socket2\"]\n");
        assert!(p.evaluate(&report).violations.is_empty());
    }

    #[test]
    fn unknown_keys_are_configuration_errors() {
        let result = toml::from_str::<Policy>("[policy]\ndeny_everything = true\n");
        assert!(result.is_err());
    }
}
