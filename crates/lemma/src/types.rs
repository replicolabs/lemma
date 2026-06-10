use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Framework {
    Anchor,
    Quasar,
    Pinocchio,
    Native,
}

impl Framework {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anchor    => "anchor",
            Self::Quasar    => "quasar",
            Self::Pinocchio => "pinocchio",
            Self::Native    => "native",
        }
    }
}

impl fmt::Display for Framework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProgramType {
    Amm,
    Lending,
    Bridge,
    Staking,
    Nft,
    Multisig,
    TokenProgram,
    Governance,
    Oracle,
    #[default]
    Other,
}

impl ProgramType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amm          => "amm",
            Self::Lending      => "lending",
            Self::Bridge       => "bridge",
            Self::Staking      => "staking",
            Self::Nft          => "nft",
            Self::Multisig     => "multisig",
            Self::TokenProgram => "token_program",
            Self::Governance   => "governance",
            Self::Oracle       => "oracle",
            Self::Other        => "other",
        }
    }
}

impl fmt::Display for ProgramType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDecl {
    pub name:          Box<str>,
    pub type_str:      Box<str>,
    pub is_mutable:    bool,
    pub has_signer:    bool,
    pub has_owner:     bool,
    pub has_has_one:   bool,
    pub has_one_field: Option<Box<str>>,
    pub is_pda:        bool,
    pub has_bump:      bool,
    pub is_unchecked:  bool,
    pub raw_constraint: Option<Box<str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArithmeticOp {
    pub op:       char,
    pub lhs:      Box<str>,
    pub rhs:      Box<str>,
    pub is_checked: bool,
    pub line:     Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpiCall {
    pub program_account: Box<str>,
    pub program_verified: bool,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionHandler {
    pub name:        Box<str>,
    pub accounts:    Vec<AccountDecl>,
    pub args:        Vec<(Box<str>, Box<str>)>,
    pub arithmetic:  Vec<ArithmeticOp>,
    pub cpi_calls:   Vec<CpiCall>,
    pub doc_comment: Option<Box<str>>,
    pub source_file: Box<str>,
}

impl InstructionHandler {
    pub fn unchecked_accounts(&self) -> impl Iterator<Item = &AccountDecl> {
        self.accounts.iter().filter(|a| a.is_unchecked)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnClass {
    MissingSignerCheck,
    MissingOwnershipCheck,
    ArithmeticError,
    InsecureInitialisation,
    OracleValidation,
    ArbitraryCpi,
    LifecycleViolation,
    PermissionlessStateWrite,
    InitWithoutPda,
    StoredFieldNeverWritten,
    PairedValidatorMismatch,
    AuthorityNotRevokedOnClose,
    Other,
}

impl VulnClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingSignerCheck        => "missing_signer_check",
            Self::MissingOwnershipCheck     => "missing_ownership_check",
            Self::ArithmeticError           => "arithmetic_error",
            Self::InsecureInitialisation    => "insecure_initialisation",
            Self::OracleValidation          => "oracle_validation",
            Self::ArbitraryCpi              => "arbitrary_cpi",
            Self::LifecycleViolation        => "lifecycle_violation",
            Self::PermissionlessStateWrite  => "permissionless_state_write",
            Self::InitWithoutPda            => "init_without_pda",
            Self::StoredFieldNeverWritten   => "stored_field_never_written",
            Self::PairedValidatorMismatch   => "paired_validator_mismatch",
            Self::AuthorityNotRevokedOnClose => "authority_not_revoked_on_close",
            Self::Other                     => "other",
        }
    }
}

impl fmt::Display for VulnClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low           => "low",
            Self::Medium        => "medium",
            Self::High          => "high",
            Self::Critical      => "critical",
        }
    }

    pub fn score_deduction(self) -> u32 {
        match self {
            Self::Informational => 0,
            Self::Low           => 1,
            Self::Medium        => 5,
            Self::High          => 10,
            Self::Critical      => 20,
        }
    }
    pub fn max_deduction(self) -> u32 {
        match self {
            Self::Informational => 0,
            Self::Low           => 5,
            Self::Medium        => 20,
            Self::High          => 30,
            Self::Critical      => 60,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapSource {
    Deterministic,
    Llm,
}

impl fmt::Display for GapSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deterministic => f.write_str("deterministic"),
            Self::Llm           => f.write_str("llm"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGap {
    pub id:               Box<str>,
    pub handler_name:     Box<str>,
    pub vuln_class:       VulnClass,
    pub severity:         Severity,
    pub description:      Box<str>,
    pub source_rule_id:   Box<str>,
    pub source:           GapSource,
    pub acknowledged:     bool,
    pub ack_reason:       Option<Box<str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QedSpecClause {
    pub clause_type: Box<str>,
    pub expression:  Box<str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerInvariants {
    pub handler_name:     Box<str>,
    pub natural_language: Box<str>,
    pub kani_assertion:   Box<str>,
    pub qedspec_forms:    Vec<QedSpecClause>,
    pub confidence:       f32,
    pub grounded_in:      Box<str>,
    pub vuln_class:       VulnClass,
    pub kani_valid:       bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KbEntry {
    pub id:               Box<str>,
    pub source_type:      Box<str>,
    pub firm:             Option<Box<str>>,
    pub program_name:     Option<Box<str>>,
    pub program_type:     Option<Box<str>>,
    pub audit_year:       Option<u32>,
    pub framework:        Option<Box<str>>,
    pub instruction_name: Option<Box<str>>,
    pub vulnerability_class: Option<Box<str>>,
    pub severity:         Option<Box<str>>,
    pub natural_language: Option<Box<str>>,
    pub kani_assertion:   Option<Box<str>>,
    pub embedding_text:   Box<str>,
    pub embedding:        Vec<f32>,
}

#[derive(Debug, Deserialize)]
pub struct KnowledgeBase {
    pub version:                    Box<str>,
    pub built_at:                   Box<str>,
    pub embedding_provider:         Box<str>,
    pub embedding_model:            Box<str>,
    pub embedding_dimensions:       u32,
    pub entry_count:                u32,
    pub audit_finding_count:        u32,
    pub framework_chunk_count:      u32,
    pub program_types_covered:      Vec<Box<str>>,
    pub vulnerability_classes_covered: Vec<Box<str>>,
    pub frameworks_covered:         Vec<Box<str>>,
    pub entries:                    Vec<KbEntry>,
}

#[derive(Debug, Clone)]
pub struct RetrievedEntry {
    pub entry: KbEntry,
    pub score: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub program:              Box<str>,
    pub framework:            Framework,
    pub program_type:         ProgramType,
    pub security_score:       u32,
    pub lemma_version:        Box<str>,
    pub kb_version:           Box<str>,
    pub analysis_timestamp:   Box<str>,
    pub git_commit:           Option<Box<str>>,
    pub gaps:                 Vec<SecurityGap>,
    pub invariants:           Vec<HandlerInvariants>,
}

impl AnalysisResult {
    pub fn compute_score(gaps: &[SecurityGap]) -> u32 {
        let mut deductions_by_severity = [0u32; 5]; 

        for gap in gaps {
            if gap.acknowledged {
                continue;
            }
            let idx = match gap.severity {
                Severity::Informational => 0,
                Severity::Low           => 1,
                Severity::Medium        => 2,
                Severity::High          => 3,
                Severity::Critical      => 4,
            };
            deductions_by_severity[idx] =
                deductions_by_severity[idx].saturating_add(gap.severity.score_deduction());
        }

        let total_deduction: u32 = deductions_by_severity
            .iter()
            .enumerate()
            .map(|(idx, &raw)| {
                let sev = match idx {
                    0 => Severity::Informational,
                    1 => Severity::Low,
                    2 => Severity::Medium,
                    3 => Severity::High,
                    _ => Severity::Critical,
                };
                raw.min(sev.max_deduction())
            })
            .sum();

        100u32.saturating_sub(total_deduction)
    }
}