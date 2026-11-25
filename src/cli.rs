//! Command-line parsing for the AHR-Endpoint agent.
//!
//! Safe by default: the agent runs in **dry-run** mode unless live mode
//! is explicitly requested with `--live`. Dry-run watches, scores, and
//! reports intended actions without loading eBPF, sending process
//! signals, or publishing NATS invariants.
//!
//! `--help` / `-h` prints usage and exits 0 without starting the agent.
//! Any unknown flag, or `--live` combined with `--dry-run`, prints usage
//! and is a hard error — the agent never falls through into any mode on
//! input it does not understand.
//!
//! One-shot commands (`--quarantine-scan`, `--embed-token`,
//! `--make-decoy`, `--probe`) act as requested and then exit without
//! starting the agent loop. They are file operations the user asked
//! for — sealing a file with a token, scanning a file, planting a
//! decoy, probing a destination — so the dry-run default does not
//! apply to them the way it applies to the agent's enforcement loop.

use std::path::PathBuf;

/// Runtime mode selected by the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Watch, score, report. Never touches a process. This is the default.
    DryRun,
    /// Enforce: matching processes WILL be suspended/killed.
    /// Only with an explicit `--live` flag.
    Live,
}

/// A one-shot command: act, print the result, exit. Never starts the
/// agent loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Sample-scan one file and print the quarantine verdict.
    /// Exit 0 = release, 3 = hold, 1 = unreadable.
    QuarantineScan(PathBuf),
    /// Embed a honeytoken in a file (idempotent) and print the token id.
    EmbedToken(PathBuf),
    /// Plant a decoy file of `kind` in `dir` and print path + token id.
    MakeDecoy { kind: String, dir: PathBuf },
    /// Pre-send probe: seal `file` with its token, watch the token
    /// for the window, and print credible / not-credible.
    /// Exit 0 = credible, 3 = not-credible, 1 = error.
    Probe { destination: String, file: PathBuf },
}

/// Parsed command-line arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    /// Run a single detection cycle, then exit. Works in both modes.
    pub once: bool,
    /// A one-shot command, when given (runs instead of the agent loop).
    pub command: Option<Command>,
    /// Quarantine staging dir for the agent loop (also `AHR_QUARANTINE_DIR`).
    pub quarantine_dir: Option<PathBuf>,
}

/// What parsing the command line produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    /// Start the agent with these arguments.
    Run(Args),
    /// Print usage and exit 0. The agent must not start.
    Help,
}

/// A command line the agent refuses to run on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A flag was given that is not recognized.
    UnknownFlag(String),
    /// `--live` and `--dry-run` were both given: ambiguous, refuse.
    ConflictingModes,
    /// A flag that takes a value was given without one.
    MissingValue(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
            ParseError::ConflictingModes => {
                write!(f, "--live and --dry-run cannot be used together")
            }
            ParseError::MissingValue(flag) => write!(f, "{flag} needs a value"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Usage text. Printed for `--help` / `-h` (exit 0) and on parse
/// errors (exit 2). Kept as one constant so help and error paths
/// can never drift apart.
pub const USAGE: &str = "AHR-Endpoint — Adaptive Hollow Reflector (research prototype, v0.3.0)

USAGE:
    ahr-endpoint [FLAGS]
    ahr-endpoint --quarantine-scan <path>
    ahr-endpoint --embed-token <path>
    ahr-endpoint --make-decoy <kind> <dir>
    ahr-endpoint --probe <destination> <file>

FLAGS:
    --dry-run     Dry-run mode (default): watch, score, and report intended
                  actions only. Never loads eBPF, never signals a process,
                  never publishes NATS invariants.
    --live        LIVE mode: enforcement active. Matching processes WILL be
                  suspended/killed. Requires an isolated test environment.
                  Prints a warning banner and waits 3 seconds before the
                  first cycle so it can be stopped with Ctrl-C.
    --once        Run a single detection cycle, then exit. Works in both
                  modes.
    --quarantine-dir <dir>
                  Quarantine staging dir for the agent loop (also
                  AHR_QUARANTINE_DIR): incoming files are sample-scanned
                  and released to released/ or held in held/.
    --help, -h    Print this help and exit. The agent does not start.

ONE-SHOT COMMANDS (act, print the result, exit — no agent loop):
    --quarantine-scan <path>
                  Sample-scan one file: magic vs claimed type, text
                  plausibility, entropy. Prints the verdict.
                  Exit 0 = release, 3 = hold, 1 = unreadable.
    --embed-token <path>
                  Embed a honeytoken in a file (idempotent — a file that
                  already carries one keeps it) and print the token id.
                  The token is the dye pack: when the file is opened or
                  read elsewhere, the canary watch logs a hit.
    --make-decoy <kind> <dir>
                  Plant a believable dummy file (kinds: credentials,
                  financial, keys, document) carrying a honeytoken and
                  registered as a decoy. Prints path + token id.
    --probe <destination> <file>
                  Pre-send credibility check: seal the file with its
                  token, then watch the token for the window
                  (AHR_PROBE_WINDOW_SECS, default 10s). Prints credible
                  or not-credible. Exit 0 = credible, 3 = not-credible.
                  An allowlist (AHR_PROBE_ALLOWLIST, colon-separated)
                  rejects unlisted destinations outright.

EXAMPLES:
    ahr-endpoint --dry-run --once     Safe first look: one cycle, no enforcement.
    ahr-endpoint --dry-run            Continuous dry-run loop (3-second cycles).
    ahr-endpoint --live --once        LIVE: one enforcement cycle (isolated host only).
    ahr-endpoint --live               LIVE: continuous enforcement loop.
    ahr-endpoint --quarantine-scan ./inbox/bundle.zip
    ahr-endpoint --embed-token ./out/report.pdf
    ahr-endpoint --make-decoy credentials ./decoys
    ahr-endpoint --probe alice@example.com ./out/report.pdf

SAFETY:
    With no flags the agent runs in dry-run mode. Live mode is explicit
    opt-in only (--live) and is never the default. Unknown flags are
    rejected: the agent prints this usage and exits without starting.
    One-shot commands act as requested (they are file operations, not
    enforcement): embedding a token modifies the file, and a probe
    watches the token file for its window.";

fn default_args() -> Args {
    Args {
        mode: Mode::DryRun,
        once: false,
        command: None,
        quarantine_dir: None,
    }
}

/// Parse an argument list (without the program name) into an outcome.
///
/// `--help` / `-h` anywhere wins and yields `ParseOutcome::Help`.
/// Unknown flags and conflicting `--live` + `--dry-run` are errors.
/// Value flags consume the following argument; a missing value is an
/// error. Only one one-shot command may be given.
pub fn parse_args<I, S>(args: I) -> Result<ParseOutcome, ParseError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = default_args();
    let mut live = false;
    let mut dry = false;
    let mut help = false;
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        // A value flag takes the next argument as its value.
        let take = |i: &mut usize| -> Result<String, ParseError> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| ParseError::MissingValue(arg.to_string()))
        };
        match arg {
            "--help" | "-h" => help = true,
            "--dry-run" => dry = true,
            "--live" => live = true,
            "--once" => parsed.once = true,
            "--quarantine-dir" => {
                parsed.quarantine_dir = Some(PathBuf::from(take(&mut i)?));
            }
            "--quarantine-scan" => {
                parsed.command = Some(Command::QuarantineScan(PathBuf::from(take(&mut i)?)));
            }
            "--embed-token" => {
                parsed.command = Some(Command::EmbedToken(PathBuf::from(take(&mut i)?)));
            }
            "--make-decoy" => {
                let kind = take(&mut i)?;
                let dir = take(&mut i)?;
                parsed.command = Some(Command::MakeDecoy {
                    kind,
                    dir: PathBuf::from(dir),
                });
            }
            "--probe" => {
                let destination = take(&mut i)?;
                let file = take(&mut i)?;
                parsed.command = Some(Command::Probe {
                    destination,
                    file: PathBuf::from(file),
                });
            }
            other => return Err(ParseError::UnknownFlag(other.to_string())),
        }
        i += 1;
    }

    if help {
        return Ok(ParseOutcome::Help);
    }
    if live && dry {
        return Err(ParseError::ConflictingModes);
    }
    parsed.mode = if live { Mode::Live } else { Mode::DryRun };
    Ok(ParseOutcome::Run(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<ParseOutcome, ParseError> {
        parse_args(args.iter().copied())
    }

    fn args(mode: Mode, once: bool) -> Args {
        Args {
            mode,
            once,
            command: None,
            quarantine_dir: None,
        }
    }

    #[test]
    fn no_flags_defaults_to_dry_run() {
        assert_eq!(run(&[]), Ok(ParseOutcome::Run(args(Mode::DryRun, false))));
    }

    #[test]
    fn dry_run_flag_is_dry_run() {
        assert_eq!(
            run(&["--dry-run"]),
            Ok(ParseOutcome::Run(args(Mode::DryRun, false)))
        );
    }

    #[test]
    fn once_flag_works_in_dry_run() {
        assert_eq!(
            run(&["--once"]),
            Ok(ParseOutcome::Run(args(Mode::DryRun, true)))
        );
        assert_eq!(
            run(&["--dry-run", "--once"]),
            Ok(ParseOutcome::Run(args(Mode::DryRun, true)))
        );
    }

    #[test]
    fn live_flag_is_live() {
        assert_eq!(
            run(&["--live"]),
            Ok(ParseOutcome::Run(args(Mode::Live, false)))
        );
        assert_eq!(
            run(&["--live", "--once"]),
            Ok(ParseOutcome::Run(args(Mode::Live, true)))
        );
    }

    #[test]
    fn help_flag_prints_help_and_starts_nothing() {
        assert_eq!(run(&["--help"]), Ok(ParseOutcome::Help));
        assert_eq!(run(&["-h"]), Ok(ParseOutcome::Help));
        // Help wins even combined with other flags: no mode is entered.
        assert_eq!(run(&["--live", "--help"]), Ok(ParseOutcome::Help));
    }

    #[test]
    fn unknown_flag_is_an_error() {
        assert_eq!(
            run(&["--bogus"]),
            Err(ParseError::UnknownFlag("--bogus".to_string()))
        );
        assert_eq!(
            run(&["--dry-run", "--wat"]),
            Err(ParseError::UnknownFlag("--wat".to_string()))
        );
    }

    #[test]
    fn conflicting_modes_are_an_error() {
        assert_eq!(run(&["--live", "--dry-run"]), Err(ParseError::ConflictingModes));
        assert_eq!(run(&["--dry-run", "--live"]), Err(ParseError::ConflictingModes));
    }

    #[test]
    fn quarantine_scan_parses() {
        assert_eq!(
            run(&["--quarantine-scan", "a.zip"]),
            Ok(ParseOutcome::Run(Args {
                mode: Mode::DryRun,
                once: false,
                command: Some(Command::QuarantineScan(PathBuf::from("a.zip"))),
                quarantine_dir: None,
            }))
        );
    }

    #[test]
    fn embed_token_parses() {
        assert_eq!(
            run(&["--embed-token", "f.pdf"]),
            Ok(ParseOutcome::Run(Args {
                mode: Mode::DryRun,
                once: false,
                command: Some(Command::EmbedToken(PathBuf::from("f.pdf"))),
                quarantine_dir: None,
            }))
        );
    }

    #[test]
    fn make_decoy_parses() {
        assert_eq!(
            run(&["--make-decoy", "credentials", "./decoys"]),
            Ok(ParseOutcome::Run(Args {
                mode: Mode::DryRun,
                once: false,
                command: Some(Command::MakeDecoy {
                    kind: "credentials".to_string(),
                    dir: PathBuf::from("./decoys"),
                }),
                quarantine_dir: None,
            }))
        );
    }

    #[test]
    fn probe_parses() {
        assert_eq!(
            run(&["--probe", "alice@example.com", "f.pdf"]),
            Ok(ParseOutcome::Run(Args {
                mode: Mode::DryRun,
                once: false,
                command: Some(Command::Probe {
                    destination: "alice@example.com".to_string(),
                    file: PathBuf::from("f.pdf"),
                }),
                quarantine_dir: None,
            }))
        );
    }

    #[test]
    fn quarantine_dir_parses() {
        assert_eq!(
            run(&["--quarantine-dir", "/tmp/q"]),
            Ok(ParseOutcome::Run(Args {
                mode: Mode::DryRun,
                once: false,
                command: None,
                quarantine_dir: Some(PathBuf::from("/tmp/q")),
            }))
        );
    }

    #[test]
    fn missing_value_is_an_error() {
        assert_eq!(
            run(&["--quarantine-scan"]),
            Err(ParseError::MissingValue("--quarantine-scan".to_string()))
        );
        assert_eq!(
            run(&["--make-decoy", "credentials"]),
            Err(ParseError::MissingValue("--make-decoy".to_string()))
        );
        assert_eq!(
            run(&["--probe", "alice@example.com"]),
            Err(ParseError::MissingValue("--probe".to_string()))
        );
    }
}
