use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name    = "lemma",
    version,
    author,
    propagate_version = true,
    max_term_width = 100,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Analyze(AnalyzeArgs),
    #[command(subcommand)]
    Kb(KbCommand),
    Search(SearchArgs),
    Init,
    Info,
    Patch(PatchArgs),
    Acknowledge(AcknowledgeArgs),
}

#[derive(Debug, Parser)]
pub struct AnalyzeArgs {
    #[arg(long, value_name = "PATH")]
    pub program: String,
    #[arg(long, value_name = "FRAMEWORK")]
    pub framework: Option<FrameworkArg>,
    #[arg(long, value_name = "TYPE", default_value = "other")]
    pub program_type: ProgramTypeArg,
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
    #[arg(long, value_name = "PATH")]
    pub output: Option<String>,
    #[arg(long, value_name = "N", default_value = "5")]
    pub top_k: usize,
    #[arg(long, value_name = "SCORE", default_value = "0.60")]
    pub min_similarity: f32,
    #[arg(long, value_name = "HANDLER")]
    pub handler: Option<String>,
    #[arg(long, default_value = "false")]
    pub no_check: bool,
    #[arg(long, default_value = "false")]
    pub no_retrieval: bool,
}

#[derive(Debug, Subcommand)]
pub enum KbCommand {
    Update,
    Status,
    Build(KbBuildArgs),
}

#[derive(Debug, Parser)]
pub struct KbBuildArgs {
    #[arg(long, value_name = "PATH")]
    pub raw: String,
    #[arg(long, value_name = "PATH", default_value = "knowledge_base.json")]
    pub output: String,
    #[arg(long, value_name = "PROVIDER", default_value = "voyage")]
    pub provider: EmbedProvider,
    #[arg(long, value_name = "MODEL", default_value = "voyage-3-large")]
    pub model: String,
    #[arg(long, value_name = "VERSION")]
    pub version: String,
}

#[derive(Debug, Parser)]
pub struct PatchArgs {
    #[arg(long, value_name = "GAP_ID")]
    pub gap: String,
    #[arg(long, conflicts_with_all = ["apply"])]
    pub preview: bool,
    #[arg(long, conflicts_with_all = ["preview"])]
    pub apply: bool,
}

#[derive(Debug, Parser)]
pub struct AcknowledgeArgs {
    #[arg(long, value_name = "GAP_ID")]
    pub gap: String,
    #[arg(long, value_name = "REASON")]
    pub reason: String,
}

#[derive(Debug, Parser)]
pub struct SearchArgs {
    pub query: String,
    #[arg(long, value_name = "N", default_value = "5")]
    pub limit: usize,
    #[arg(long, value_name = "SCORE", default_value = "0.50")]
    pub min_similarity: f32,
    #[arg(long, value_name = "FORMAT", default_value = "text")]
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FrameworkArg {
    Anchor,
    Quasar,
    Pinocchio,
    Native,
}

impl From<FrameworkArg> for crate::types::Framework {
    fn from(arg: FrameworkArg) -> Self {
        match arg {
            FrameworkArg::Anchor    => Self::Anchor,
            FrameworkArg::Quasar    => Self::Quasar,
            FrameworkArg::Pinocchio => Self::Pinocchio,
            FrameworkArg::Native    => Self::Native,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum ProgramTypeArg {
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

impl From<ProgramTypeArg> for crate::types::ProgramType {
    fn from(arg: ProgramTypeArg) -> Self {
        match arg {
            ProgramTypeArg::Amm          => Self::Amm,
            ProgramTypeArg::Lending      => Self::Lending,
            ProgramTypeArg::Bridge       => Self::Bridge,
            ProgramTypeArg::Staking      => Self::Staking,
            ProgramTypeArg::Nft          => Self::Nft,
            ProgramTypeArg::Multisig     => Self::Multisig,
            ProgramTypeArg::TokenProgram => Self::TokenProgram,
            ProgramTypeArg::Governance   => Self::Governance,
            ProgramTypeArg::Oracle       => Self::Oracle,
            ProgramTypeArg::Other        => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EmbedProvider {
    Voyage,
    Openai,
}

impl EmbedProvider {
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Voyage => "voyage",
            Self::Openai => "openai",
        }
    }
}