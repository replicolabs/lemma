use owo_colors::OwoColorize;

pub fn print() {
    const ART: &str = r#" _
| | ___ _ __ ___  _ __ ___   __ _
| |/ _ \ '_ ` _ \| '_ ` _ \ / _` |
| |  __/ | | | | | | | | | | (_| |
|_|\___|_| |_| |_|_| |_| |_|\__,_|"#;
    eprintln!("{}", ART.white());
    eprintln!("{}", "security analysis for solana programs".dimmed());
    eprintln!();
}
