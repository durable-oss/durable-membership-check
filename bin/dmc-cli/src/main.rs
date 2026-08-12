//! Entry point: argument parsing for one-shot mode, and the serve loop.
//!
//! See the crate documentation in `lib.rs` for the protocol. This file is
//! only the two front doors onto [`dmc_cli::Session`].

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use dmc_cli::Session;
use dmc_cli::wire::{ParamsSpec, Request, Response};

/// Usage text, printed for `--help` and for a malformed invocation.
const USAGE: &str = "\
dmc-cli — command-line access to durable-membership-check filters

USAGE:
    dmc-cli <COMMAND> [OPTIONS]

COMMANDS:
    list
        Print every linked filter implementation with its capabilities.

    describe <NAME>
        Print one implementation, resolved by exact id or family alias.

    build <NAME> [OPTIONS]
        Build a filter and print its accounting. The filter is discarded when
        the process exits; use `serve` to keep it.

    query <NAME> [OPTIONS] --probes <HEX,...>
        Build a filter, then report membership for each probe key.

    serve
        Read one JSON command per line on stdin, write one JSON reply per line
        on stdout. Filters persist across commands under integer handles.

OPTIONS:
    --keys <HEX,...>          Comma-separated hex-encoded keys.
    --keys-file <PATH>        One hex-encoded key per line. Repeatable, and
                              combines with --keys.
    --probes <HEX,...>        Comma-separated hex-encoded probe keys.
    --probes-file <PATH>      One hex-encoded probe key per line.
    --expected-items <N>      Sizing hint. Defaults to the supplied key count.
    --fpr <RATE>              Target false positive rate. Defaults to 0.01.
    --seed <N>                Hash seed. Defaults to 0.

Keys are hex because keys are arbitrary bytes: a key may contain a NUL, a lone
0xFF, or an invalid UTF-8 sequence, and hex carries all three unchanged.

All output is JSON. Failures are printed as {\"ok\":false,...} with a
machine-readable \"kind\", and exit status 1.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatches on the subcommand.
///
/// Returns `Err` only for a usage problem. A command that runs and fails prints
/// its JSON error and still returns `Err`, so the exit status is meaningful to
/// a shell while the machine-readable detail goes to stdout.
fn run(args: &[String]) -> Result<(), String> {
    let Some(command) = args.first() else {
        return Err(USAGE.to_string());
    };

    match command.as_str() {
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        "serve" => serve(),
        "list" => one_shot(Request::List),
        "describe" => {
            let name = args
                .get(1)
                .ok_or("describe needs a filter name; see --help")?;
            one_shot(Request::Describe { name: name.clone() })
        }
        "build" => {
            let (name, options) = split_name(args)?;
            one_shot(Request::Build {
                name,
                keys_hex: options.keys,
                params: options.params,
            })
        }
        "query" => {
            let (name, options) = split_name(args)?;
            query(&name, options)
        }
        other => Err(format!("unknown command `{other}`; see --help")),
    }
}

/// Runs one command through a fresh session and prints the reply.
fn one_shot(request: Request) -> Result<(), String> {
    let mut session = Session::new();

    let Some(response) = session.handle(request) else {
        // `quit` is unreachable here: no subcommand maps to it.
        return Ok(());
    };

    emit(&response)
}

/// Builds a filter, then reports membership for the probe set.
///
/// Two commands rather than one, because a probe result is only meaningful
/// alongside the filter that produced it, and a caller running `query` wants
/// both without managing a handle.
fn query(name: &str, options: Options) -> Result<(), String> {
    if options.probes.is_empty() {
        return Err("query needs --probes or --probes-file; see --help".to_string());
    }

    let mut session = Session::new();

    let built = session
        .handle(Request::Build {
            name: name.to_string(),
            keys_hex: options.keys,
            params: options.params,
        })
        .ok_or("build did not produce a reply")?;

    // A failed build has nothing to query; report it and stop.
    let handle = match &built {
        Response::Ok(dmc_cli::wire::Payload::Built { handle, .. }) => *handle,
        _ => return emit(&built),
    };

    let answers = session
        .handle(Request::Contains {
            handle,
            keys_hex: options.probes,
        })
        .ok_or("contains did not produce a reply")?;

    emit(&answers)
}

/// Prints a reply as one line of JSON.
///
/// Returns `Err` for an error reply so the exit status reflects it, while the
/// structured detail still reaches stdout for a machine to read.
fn emit(response: &Response) -> Result<(), String> {
    let line =
        serde_json::to_string(response).map_err(|why| format!("could not encode reply: {why}"))?;
    println!("{line}");

    match response {
        Response::Ok(_) => Ok(()),
        // Already printed as JSON; the stderr copy would be noise.
        Response::Err { .. } => Err(String::new()),
    }
}

/// Reads commands from stdin until EOF or `quit`.
///
/// One reply per command, flushed immediately: a client that writes a command
/// and blocks on a read would otherwise deadlock behind a buffer.
fn serve() -> Result<(), String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut session = Session::new();

    for line in stdin.lock().lines() {
        let line = line.map_err(|why| format!("could not read stdin: {why}"))?;

        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => match session.handle(request) {
                Some(response) => response,
                // `quit`: stop without replying.
                None => break,
            },
            // A malformed command is a reply, not a fatal error. The session
            // stays usable so a suite can test bad input mid-stream.
            Err(why) => Response::client_error("bad_request", why.to_string()),
        };

        let encoded = serde_json::to_string(&response)
            .map_err(|why| format!("could not encode reply: {why}"))?;

        writeln!(stdout, "{encoded}").map_err(|why| format!("could not write stdout: {why}"))?;
        stdout
            .flush()
            .map_err(|why| format!("could not flush stdout: {why}"))?;
    }

    Ok(())
}

/// Options gathered from the flags after a subcommand.
#[derive(Default)]
struct Options {
    /// Hex-encoded member keys.
    keys: Vec<String>,

    /// Hex-encoded probe keys.
    probes: Vec<String>,

    /// Build parameters.
    params: ParamsSpec,
}

/// Pulls the filter name off the front and parses the remaining flags.
fn split_name(args: &[String]) -> Result<(String, Options), String> {
    let name = args
        .get(1)
        .ok_or_else(|| format!("{} needs a filter name; see --help", args[0]))?;

    Ok((name.clone(), parse_options(&args[2..])?))
}

/// Parses the flag list.
///
/// Hand-rolled rather than pulled from a parser crate: the grammar is eight
/// flags with no subcommand nesting, and the CLI is a test fixture whose
/// dependency footprint is worth keeping at zero beyond serde.
fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut index = 0;

    while index < args.len() {
        let flag = args[index].as_str();

        // Every flag here takes exactly one value.
        let value = || -> Result<&String, String> {
            args.get(index + 1)
                .ok_or_else(|| format!("{flag} needs a value"))
        };

        match flag {
            "--keys" => options.keys.extend(split_list(value()?)),
            "--probes" => options.probes.extend(split_list(value()?)),
            "--keys-file" => options.keys.extend(read_lines(value()?)?),
            "--probes-file" => options.probes.extend(read_lines(value()?)?),
            "--expected-items" => {
                options.params.expected_items = Some(value()?.parse().map_err(|_| {
                    format!(
                        "--expected-items needs an integer, got `{}`",
                        value().unwrap_or(&String::new())
                    )
                })?);
            }
            "--fpr" => {
                // Parsed but not range-checked: sending an out-of-range rate
                // and reading back InvalidParameter is a test case.
                options.params.false_positive_rate = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--fpr needs a number".to_string())?,
                );
            }
            "--seed" => {
                options.params.seed = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--seed needs an unsigned integer".to_string())?,
                );
            }
            other => return Err(format!("unknown option `{other}`; see --help")),
        }

        index += 2;
    }

    Ok(options)
}

/// Splits a comma-separated list, discarding empty entries.
///
/// An empty entry would decode to an empty key, which is legal but is far more
/// likely to be a trailing comma than a deliberate `b""`. A caller who wants
/// the empty key passes it through `--keys-file`, where a blank line is
/// unambiguous.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Reads one hex-encoded key per line.
///
/// A blank line is the empty key, which is why this path exists alongside
/// `--keys`. Trailing whitespace is trimmed, since it is almost always an
/// artifact of how the file was written.
fn read_lines(path: &str) -> Result<Vec<String>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|why| format!("could not read {path}: {why}"))?;

    Ok(text
        .lines()
        .map(|line| line.trim_end().to_string())
        .collect())
}
