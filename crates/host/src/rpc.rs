//! The JSON-RPC client, and the content-addressed cache in front of it.
//!
//! **RPC access is confined to the manual refresh command** (S25 must-be-exact
//! 6). Everything else — re-recording a witness, the determinism test, CI —
//! runs an [`Rpc`] built by [`Rpc::offline`], which answers from the cache and
//! returns an error naming the call on a miss. A test that reaches the network
//! is a test that fails on a machine with no network, and a fixture that
//! depends on a live chain is not a fixture.
//!
//! # Transport
//!
//! `curl`, as a subprocess. The alternative is an HTTP client crate, which
//! drags a TLS stack into a repository whose runtime dependencies are
//! serialization, rayon, CLI and error handling (master rule 2, anti-goal 6) —
//! for one command a human runs by hand. The endpoint goes to `curl` through a
//! `--config -` on stdin rather than on the command line, so an API key in the
//! URL does not appear in the process table.
//!
//! # The cache
//!
//! One file per `(method, params)` pair, named by a Poseidon2 digest of both,
//! under the fixture directory. Content-addressing is what makes a re-record
//! reproducible: the same call asks for the same file and gets the same bytes,
//! whatever the chain has done since. `docs/spec/witness-pipeline.md` §2.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::json::{self, Json};

/// How many times a transport or 5xx failure is retried before the call fails.
/// S25 must-be-exact 6.
const RETRIES: u32 = 5;

/// The first backoff, doubled each retry: 1 s, 2 s, 4 s, 8 s, 16 s.
const BACKOFF_MILLIS: u64 = 1_000;

/// How long one `curl` may take. An `eth_getProof` over a deep account is the
/// slow one.
const TIMEOUT_SECONDS: u64 = 120;

/// The environment variable the endpoint comes from.
pub const ENDPOINT_VAR: &str = "ETH_RPC_URL";

/// A JSON-RPC endpoint with a cache in front of it, or a cache alone.
pub struct Rpc {
    cache: PathBuf,
    /// `None` is offline: a miss is an error, never a request.
    endpoint: Option<String>,
}

impl Rpc {
    /// A cache-only client. A call the cache does not hold is an error naming
    /// the call, so an offline run cannot silently default.
    pub fn offline(cache: impl Into<PathBuf>) -> Rpc {
        Rpc {
            cache: cache.into(),
            endpoint: None,
        }
    }

    /// A client that fills its cache from `endpoint` on a miss.
    pub fn online(cache: impl Into<PathBuf>, endpoint: impl Into<String>) -> Rpc {
        Rpc {
            cache: cache.into(),
            endpoint: Some(endpoint.into()),
        }
    }

    /// A client reading its endpoint from `ETH_RPC_URL`.
    pub fn from_env(cache: impl Into<PathBuf>) -> Result<Rpc, String> {
        let endpoint = std::env::var(ENDPOINT_VAR)
            .map_err(|_| format!("{ENDPOINT_VAR} is not set, and a refresh needs an endpoint"))?;
        if endpoint.is_empty() {
            return Err(format!("{ENDPOINT_VAR} is empty"));
        }
        Ok(Rpc::online(cache, endpoint))
    }

    /// Whether this client may reach the network.
    pub fn is_online(&self) -> bool {
        self.endpoint.is_some()
    }

    /// The directory the cache lives in.
    pub fn cache_dir(&self) -> &Path {
        &self.cache
    }

    /// Call `method` with `params`, a JSON array written by the caller, and
    /// return the response's `result`.
    ///
    /// A JSON-RPC `error` member is a hard failure: a node that says it cannot
    /// answer is not a node whose answer may be guessed.
    pub fn call(&self, method: &str, params: &str) -> Result<Json, String> {
        let path = self.cache.join(cache_name(method, params));
        if let Ok(text) = std::fs::read_to_string(&path) {
            return result_of(&text, method);
        }
        let endpoint = self.endpoint.as_ref().ok_or_else(|| {
            format!(
                "rpc: {method}{params} is not cached at {}, and this client is offline. \
                 Run the refresh command with {ENDPOINT_VAR} set.",
                path.display()
            )
        })?;
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
        let text = post(endpoint, &body)?;
        // Parsed before it is cached: a cache is a record of answers, and an
        // error response or a malformed body is not one.
        let value = result_of(&text, method)?;
        std::fs::create_dir_all(&self.cache)
            .map_err(|e| format!("rpc: {}: {e}", self.cache.display()))?;
        std::fs::write(&path, &text).map_err(|e| format!("rpc: {}: {e}", path.display()))?;
        Ok(value)
    }
}

/// The `result` member of a JSON-RPC response, or the error it carries.
fn result_of(text: &str, method: &str) -> Result<Json, String> {
    let value = json::parse(text).map_err(|e| format!("rpc: {method}: {e}"))?;
    if let Some(error) = value.get("error") {
        let message = error
            .get("message")
            .and_then(Json::as_str)
            .unwrap_or("no message");
        return Err(format!("rpc: {method} answered an error: {message}"));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| format!("rpc: {method}'s response has no result member"))
}

/// The cache file's name: the method, for a human reading the directory, then
/// a digest of the method and the parameters, which is what makes it
/// content-addressed.
///
/// Poseidon2 through the repository's own transcript, rather than a hash
/// dependency: [`transcript::io_digest`] is the frozen digest of a pair of
/// byte strings and this is a pair of byte strings. It binds nothing here —
/// the digest is a *name*, and a collision would serve one call's answer to
/// another, which the re-record diff of acceptance 1 would catch at once.
fn cache_name(method: &str, params: &str) -> String {
    let digest = transcript::io_digest(method.as_bytes(), params.as_bytes());
    let mut hex = String::with_capacity(32);
    // The low sixteen bytes of the canonical encoding: 128 bits of name is
    // more than a fixture directory of a few thousand files needs.
    for byte in digest.to_bytes().iter().take(16) {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("{method}-{hex}.json")
}

/// POST `body` to `endpoint`, retrying a transport or 5xx failure
/// [`RETRIES`] times with exponential backoff, then failing hard.
///
/// A 4xx is **not** retried: a bad key or a malformed request will say the
/// same thing five times, and five identical refusals are a worse error
/// message than one.
fn post(endpoint: &str, body: &str) -> Result<String, String> {
    let mut wait = BACKOFF_MILLIS;
    let mut last = String::new();
    for attempt in 0..=RETRIES {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(wait));
            wait *= 2;
        }
        match curl(endpoint, body) {
            Ok(Answer::Ok(text)) => return Ok(text),
            Ok(Answer::Status(code, text)) if (500..600).contains(&code) => {
                last = format!("HTTP {code}: {}", first_line(&text));
            }
            Ok(Answer::Status(code, text)) => {
                return Err(format!("rpc: HTTP {code}: {}", first_line(&text)));
            }
            Err(transport) => last = transport,
        }
    }
    Err(format!(
        "rpc: {} attempts failed, the last with {last}",
        RETRIES + 1
    ))
}

enum Answer {
    Ok(String),
    Status(u32, String),
}

/// One `curl` run. `Err` is a transport failure — curl could not complete the
/// request at all — and `Answer::Status` is an HTTP status other than 200.
fn curl(endpoint: &str, body: &str) -> Result<Answer, String> {
    use std::io::Write;

    let mut child = Command::new("curl")
        .args([
            // The endpoint arrives on stdin, below, so an API key in it stays
            // out of the process table.
            "--config",
            "-",
            "--silent",
            "--show-error",
            "--max-time",
            &TIMEOUT_SECONDS.to_string(),
            "--request",
            "POST",
            "--header",
            "content-type: application/json",
            "--data-binary",
            "@-",
            // The status code, after the body, on its own line.
            "--write-out",
            "\n%{http_code}",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("rpc: curl did not start: {e}"))?;

    // `--config -` and `--data-binary @-` both read stdin, in that order: curl
    // consumes the config first and the request body is what is left.
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let config = format!("url = \"{endpoint}\"\n");
    stdin
        .write_all(config.as_bytes())
        .and_then(|()| stdin.write_all(body.as_bytes()))
        .map_err(|e| format!("rpc: writing curl's stdin: {e}"))?;
    drop(stdin);

    let out = child
        .wait_with_output()
        .map_err(|e| format!("rpc: waiting for curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "rpc: curl exited {}: {}",
            out.status.code().unwrap_or(-1),
            first_line(&String::from_utf8_lossy(&out.stderr))
        ));
    }
    let text = String::from_utf8(out.stdout)
        .map_err(|_| String::from("rpc: curl's output is not UTF-8"))?;
    let split = text
        .rfind('\n')
        .ok_or_else(|| String::from("rpc: curl wrote no status line"))?;
    let code: u32 = text[split + 1..]
        .trim()
        .parse()
        .map_err(|_| format!("rpc: curl's status line is {:?}", &text[split + 1..]))?;
    let body = text[..split].to_string();
    if code == 200 {
        Ok(Answer::Ok(body))
    } else {
        Ok(Answer::Status(code, body))
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cache_name_is_a_function_of_the_call() {
        let a = cache_name("eth_getProof", r#"["0x01",[],"0x2"]"#);
        assert_eq!(a, cache_name("eth_getProof", r#"["0x01",[],"0x2"]"#));
        assert_ne!(a, cache_name("eth_getProof", r#"["0x01",[],"0x3"]"#));
        assert_ne!(a, cache_name("eth_getCode", r#"["0x01",[],"0x2"]"#));
        assert!(a.starts_with("eth_getProof-") && a.ends_with(".json"));
        assert_eq!(a.len(), "eth_getProof-".len() + 32 + ".json".len());
    }

    #[test]
    fn an_offline_miss_names_the_call() {
        let rpc = Rpc::offline(std::env::temp_dir().join("apogee-no-such-cache"));
        let error = rpc.call("eth_getCode", "[]").expect_err("a miss");
        assert!(error.contains("eth_getCode"), "{error}");
        assert!(error.contains("offline"), "{error}");
    }

    #[test]
    fn a_cached_answer_needs_no_endpoint() {
        let dir = std::env::temp_dir().join("apogee-rpc-cache-test");
        std::fs::create_dir_all(&dir).expect("a cache directory");
        let path = dir.join(cache_name("eth_chainId", "[]"));
        std::fs::write(&path, r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#).expect("written");
        let rpc = Rpc::offline(&dir);
        assert_eq!(
            rpc.call("eth_chainId", "[]").expect("a hit").as_str(),
            Some("0x1")
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_error_response_is_a_failure() {
        let dir = std::env::temp_dir().join("apogee-rpc-error-test");
        std::fs::create_dir_all(&dir).expect("a cache directory");
        let path = dir.join(cache_name("eth_getProof", "[]"));
        std::fs::write(
            &path,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"missing trie node"}}"#,
        )
        .expect("written");
        let error = Rpc::offline(&dir)
            .call("eth_getProof", "[]")
            .expect_err("an error response");
        assert!(error.contains("missing trie node"), "{error}");
        std::fs::remove_file(&path).ok();
    }
}
