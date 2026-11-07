//! Montagem do relatório: score, nota, resumo, ordenação e truncamento.

use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::repo_url::RepoRef;
use crate::scanner::{Category, RawFinding, Severity};

pub const MAX_FINDINGS: usize = 500;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Finding {
    pub id: Uuid,
    pub rule_id: String,
    pub category: Category,
    pub severity: Severity,
    pub file: String,
    pub line: u32,
    pub snippet: String,
    pub description: String,
    pub fix_prompt: String,
}

#[derive(Debug, Clone, Default, Serialize, ToSchema, PartialEq, Eq)]
pub struct BySeverity {
    #[serde(rename = "CRITICAL")]
    pub critical: u64,
    #[serde(rename = "HIGH")]
    pub high: u64,
    #[serde(rename = "MEDIUM")]
    pub medium: u64,
    #[serde(rename = "LOW")]
    pub low: u64,
}

#[derive(Debug, Clone, Default, Serialize, ToSchema, PartialEq, Eq)]
pub struct ByCategory {
    #[serde(rename = "SECRET")]
    pub secret: u64,
    #[serde(rename = "HIDDEN_UNICODE")]
    pub hidden_unicode: u64,
    #[serde(rename = "SLOPSQUATTING")]
    pub slopsquatting: u64,
    #[serde(rename = "INSECURE_CODE")]
    pub insecure_code: u64,
}

#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct Summary {
    pub by_severity: BySeverity,
    pub by_category: ByCategory,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScanReport {
    pub scan_id: Uuid,
    pub repo: RepoRef,
    pub score: u32,
    /// A, B, C, D ou F.
    pub grade: String,
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub bytes_downloaded: u64,
    pub duration_ms: u64,
    pub truncated: bool,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

pub struct ReportInput {
    pub repo: RepoRef,
    pub findings: Vec<RawFinding>,
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub bytes_downloaded: u64,
    pub duration_ms: u64,
}

pub fn score(findings: &[RawFinding]) -> u32 {
    let penalty: u64 = findings
        .iter()
        .map(|f| u64::from(f.severity.weight()))
        .sum();
    u32::try_from(100u64.saturating_sub(penalty)).unwrap_or(0)
}

pub fn grade(score: u32) -> &'static str {
    match score {
        90.. => "A",
        80..=89 => "B",
        70..=79 => "C",
        50..=69 => "D",
        _ => "F",
    }
}

pub fn summarize(findings: &[RawFinding]) -> Summary {
    let mut s = Summary::default();
    for f in findings {
        match f.severity {
            Severity::Critical => s.by_severity.critical += 1,
            Severity::High => s.by_severity.high += 1,
            Severity::Medium => s.by_severity.medium += 1,
            Severity::Low => s.by_severity.low += 1,
        }
        match f.category {
            Category::Secret => s.by_category.secret += 1,
            Category::HiddenUnicode => s.by_category.hidden_unicode += 1,
            Category::Slopsquatting => s.by_category.slopsquatting += 1,
            Category::InsecureCode => s.by_category.insecure_code += 1,
        }
    }
    s
}

/// Score e resumo consideram TODOS os achados; a lista é ordenada e cortada em 500.
pub fn build_report(input: ReportInput) -> ScanReport {
    let mut findings = input.findings;
    let score = score(&findings);
    let summary = summarize(&findings);
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule_id.cmp(b.rule_id))
    });
    let truncated = findings.len() > MAX_FINDINGS;
    findings.truncate(MAX_FINDINGS);
    ScanReport {
        scan_id: Uuid::new_v4(),
        repo: input.repo,
        score,
        grade: grade(score).to_string(),
        files_scanned: input.files_scanned,
        files_skipped: input.files_skipped,
        bytes_downloaded: input.bytes_downloaded,
        duration_ms: input.duration_ms,
        truncated,
        summary,
        findings: findings
            .into_iter()
            .map(|f| Finding {
                id: Uuid::new_v4(),
                rule_id: f.rule_id.to_string(),
                category: f.category,
                severity: f.severity,
                file: f.file,
                line: f.line,
                snippet: f.snippet,
                description: f.description,
                fix_prompt: f.fix_prompt,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(sev: Severity, file: &str, line: u32) -> RawFinding {
        RawFinding {
            rule_id: "x.y",
            category: Category::InsecureCode,
            severity: sev,
            file: file.to_string(),
            line,
            snippet: String::new(),
            description: String::new(),
            fix_prompt: String::new(),
        }
    }

    fn repo() -> RepoRef {
        RepoRef {
            owner: "o".into(),
            name: "r".into(),
            url: "https://github.com/o/r".into(),
        }
    }

    #[test]
    fn grade_nos_limites() {
        assert_eq!(grade(100), "A");
        assert_eq!(grade(90), "A");
        assert_eq!(grade(89), "B");
        assert_eq!(grade(80), "B");
        assert_eq!(grade(79), "C");
        assert_eq!(grade(70), "C");
        assert_eq!(grade(69), "D");
        assert_eq!(grade(50), "D");
        assert_eq!(grade(49), "F");
        assert_eq!(grade(0), "F");
    }

    #[test]
    fn score_por_peso_e_piso_zero() {
        assert_eq!(score(&[]), 100);
        let f = vec![
            raw(Severity::Critical, "a", 1),
            raw(Severity::High, "a", 1),
            raw(Severity::Medium, "a", 1),
            raw(Severity::Low, "a", 1),
        ];
        assert_eq!(score(&f), 100 - 25 - 10 - 4 - 1);
        let many: Vec<RawFinding> = (0..10).map(|i| raw(Severity::Critical, "a", i)).collect();
        assert_eq!(score(&many), 0);
        // Exatamente 10 pontos de penalidade => 90 => A.
        assert_eq!(grade(score(&[raw(Severity::High, "a", 1)])), "A");
    }

    #[test]
    fn ordena_por_severidade_arquivo_linha() {
        let r = build_report(ReportInput {
            repo: repo(),
            findings: vec![
                raw(Severity::Low, "a.ts", 1),
                raw(Severity::Critical, "b.ts", 9),
                raw(Severity::Critical, "a.ts", 5),
                raw(Severity::Critical, "a.ts", 2),
                raw(Severity::Medium, "a.ts", 1),
            ],
            files_scanned: 2,
            files_skipped: 0,
            bytes_downloaded: 10,
            duration_ms: 1,
        });
        let got: Vec<(Severity, &str, u32)> = r
            .findings
            .iter()
            .map(|f| (f.severity, f.file.as_str(), f.line))
            .collect();
        assert_eq!(
            got,
            vec![
                (Severity::Critical, "a.ts", 2),
                (Severity::Critical, "a.ts", 5),
                (Severity::Critical, "b.ts", 9),
                (Severity::Medium, "a.ts", 1),
                (Severity::Low, "a.ts", 1),
            ]
        );
        assert!(!r.truncated);
        assert_eq!(r.summary.by_severity.critical, 3);
        assert_eq!(r.summary.by_category.insecure_code, 5);
    }

    #[test]
    fn trunca_em_500() {
        let findings: Vec<RawFinding> = (0..501).map(|i| raw(Severity::Low, "a", i)).collect();
        let r = build_report(ReportInput {
            repo: repo(),
            findings,
            files_scanned: 1,
            files_skipped: 0,
            bytes_downloaded: 0,
            duration_ms: 0,
        });
        assert_eq!(r.findings.len(), 500);
        assert!(r.truncated);
        assert_eq!(r.summary.by_severity.low, 501);

        let findings: Vec<RawFinding> = (0..500).map(|i| raw(Severity::Low, "a", i)).collect();
        let r = build_report(ReportInput {
            repo: repo(),
            findings,
            files_scanned: 1,
            files_skipped: 0,
            bytes_downloaded: 0,
            duration_ms: 0,
        });
        assert_eq!(r.findings.len(), 500);
        assert!(!r.truncated);
    }

    #[test]
    fn json_tem_chaves_do_contrato() {
        let r = build_report(ReportInput {
            repo: repo(),
            findings: vec![raw(Severity::High, "a", 1)],
            files_scanned: 1,
            files_skipped: 0,
            bytes_downloaded: 0,
            duration_ms: 0,
        });
        let v = serde_json::to_value(&r).expect("serializa");
        assert_eq!(v["summary"]["by_severity"]["HIGH"], 1);
        assert_eq!(v["summary"]["by_category"]["INSECURE_CODE"], 1);
        assert_eq!(v["findings"][0]["severity"], "HIGH");
        assert_eq!(v["findings"][0]["category"], "INSECURE_CODE");
    }
}
