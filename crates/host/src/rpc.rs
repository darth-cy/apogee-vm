//! The minimal Ethereum JSON-RPC client, and the cache that keeps CI off the
//! network.
//!
//! S25's must-be-exact 6 asks for "a minimal JSON-RPC client rather than an
//! Ethereum SDK", reading its endpoint from `ETH_RPC_URL`, caching responses
//! content-addressed under the fixture directory, and retrying transport and
//! 5xx failures five times with exponential backoff before failing hard. This
//! module is all of that and nothing else: it knows about requests, responses,
//! retries and files. It knows nothing about blocks, accounts or proofs —
//! `crate::recorder` does.
//!
//! # Why `curl`
//!
//! Every mainnet endpoint is TLS-only and this workspace has no HTTP client, no
//! TLS and no async runtime — master anti-goal 6 makes the allowed runtime
//! dependency list exhaustive and anti-goal 7 bans `tokio` by name. Hand-rolling
//! TLS is not what "own the crypto" means; it means the *proving system's*
//! cryptography. So the JSON-RPC client is ours — request framing, the retry
//! policy, the cache — and only the HTTPS bytes are `curl`'s, spawned through
//! `std::process::Command` exactly as this repository already spawns `cargo`,
//! `qemu-riscv32` and `llvm-objdump`. `curl` is an undeclared host tool of the
//! same class as those, and like them it is reachable only from a manual path:
//! CI never runs this module (owner's decision, recorded in
//! `docs/handoff/S25-block.md`).
//!
//! One caveat worth stating rather than hiding: the endpoint carries an API key
//! and is passed to `curl` on its command line, so it is visible in `ps` output
//! on the machine doing the refresh. The request body goes over stdin, so the
//! block data is not. Keeping the key off `argv` as well would mean a `curl`
//! config file with its own quoting rules, which is more ways to be wrong for a
//! developer-machine-only path.
//!
//! # The cache is the only thing CI sees
//!
//! A [`Rpc`] with no endpoint answers from the cache and refuses a miss. That is
//! how `crates/host/tests/` and the recorder's determinism test run with no
//! network: the committed cache is the snapshot, and a request the snapshot does
//! not answer is an error naming the method rather than a silent default.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

/// The environment variable the endpoint comes from. Never a committed file:
/// the URL carries an API key.
pub const ENDPOINT_VAR: &str = "ETH_RPC_URL";

/// How many times a transport or 5xx failure is retried before failing hard.
pub const ATTEMPTS: u32 = 5;

/// The first backoff, doubled after every failed attempt: 1 s, 2 s, 4 s, 8 s.
/// Four waits for five attempts, so a hard failure takes about fifteen seconds
/// to admit.
const BACKOFF_MILLIS: u64 = 1_000;

/// Seconds `curl` is given for one request. `eth_getProof` on a busy contract is
/// slow, and a timeout is a transport failure, which is retried.
const TIMEOUT_SECONDS: u64 = 60;

/// A JSON-RPC endpoint and the cache in front of it.
///
/// Requests are answered from the cache when it has them. A miss goes to the
/// network if an endpoint was given, and is written to the cache on success; a
/// miss with no endpoint is an error. There is no invalidation: a cached
/// response is the answer for the `(method, params)` that produced it, and every
/// request this client makes names a specific block, so the answer cannot go
/// stale.
pub struct Rpc {
    endpoint: Option<String>,
    cache: PathBuf,
    /// Requests answered from the cache, and requests that reached the network.
    /// The refresh command prints both; a recording that claims to be
    /// deterministic and made `n` network calls on its second run is not.
    pub hits: u64,
    /// Requests that reached the network.
    pub misses: u64,
}

impl Rpc {
    /// A client over `cache`, using `ETH_RPC_URL` if it is set.
    ///
    /// The directory is created when a response is first written, not here: a
    /// cache-only client that answers every request never touches the disk.
    pub fn new(cache: PathBuf) -> Rpc {
        let endpoint = match std::env::var(ENDPOINT_VAR) {
            Ok(url) if !url.trim().is_empty() => Some(url),
            _ => None,
        };
        Rpc {
            endpoint,
            cache,
            hits: 0,
            misses: 0,
        }
    }

    /// A client that may only read the cache, whatever the environment says.
    ///
    /// This is what a test uses: a suite that silently fell back to the network
    /// would pass on one machine and fail on every other, and would put an API
    /// key in a CI log the first time somebody set one.
    pub fn cached(cache: PathBuf) -> Rpc {
        Rpc {
            endpoint: None,
            cache,
            hits: 0,
            misses: 0,
        }
    }

    /// Whether this client may reach the network.
    pub fn online(&self) -> bool {
        self.endpoint.is_some()
    }

    /// The JSON-RPC `result` for one call, from the cache or from the endpoint.
    ///
    /// A JSON-RPC `error` member is a hard failure and is not retried: the
    /// request reached a server that understood it and refused it, so trying
    /// again asks the same question of the same server.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let request = request_body(method, &params);
        let path = self
            .cache
            .join(format!("{}.json", digest_hex(request.as_bytes())));
        if let Ok(bytes) = std::fs::read(&path) {
            self.hits += 1;
            return serde_json::from_slice(&bytes).map_err(|e| {
                format!("the cached response at {} is not JSON: {e}", path.display())
            });
        }
        let Some(endpoint) = self.endpoint.clone() else {
            return Err(format!(
                "no cached response for {method} and {ENDPOINT_VAR} is not set \
                 (looked for {})",
                path.display()
            ));
        };
        let result = self.fetch(&endpoint, method, &request)?;
        self.misses += 1;
        std::fs::create_dir_all(&self.cache)
            .map_err(|e| format!("cannot create {}: {e}", self.cache.display()))?;
        // Pretty-printed, so that a cache entry is a readable record of what the
        // chain answered rather than one very long line in a diff.
        let text = serde_json::to_string_pretty(&result)
            .map_err(|e| format!("cannot re-encode the {method} response: {e}"))?;
        std::fs::write(&path, text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        Ok(result)
    }

    /// One call that neither reads nor writes the cache.
    ///
    /// For the one request whose answer is *time-dependent*: "what is the
    /// finalized head". Caching that would pin every future refresh to
    /// whatever the chain looked like the first time anybody ran one, which is
    /// the opposite of a freshness command. Everything downstream names an
    /// explicit height and caches.
    pub fn call_uncached(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let request = request_body(method, &params);
        let Some(endpoint) = self.endpoint.clone() else {
            return Err(format!(
                "{method} needs {ENDPOINT_VAR} and cannot be cached"
            ));
        };
        let result = self.fetch(&endpoint, method, &request)?;
        self.misses += 1;
        Ok(result)
    }

    /// One request, retried [`ATTEMPTS`] times with exponential backoff, then
    /// failed hard.
    fn fetch(&self, endpoint: &str, method: &str, request: &str) -> Result<Value, String> {
        let mut wait = BACKOFF_MILLIS;
        let mut last = String::new();
        for attempt in 1..=ATTEMPTS {
            match post(endpoint, request) {
                Ok((status, body)) if (200..300).contains(&status) => {
                    return decode(method, &body);
                }
                Ok((status, body)) if status >= 500 || status == 429 => {
                    last = format!("HTTP {status}: {}", first_line(&body));
                }
                Ok((status, body)) => {
                    // 4xx other than 429 is this client's fault — a bad key, a
                    // method the endpoint does not serve — and retrying it just
                    // asks the same question four more times.
                    return Err(format!(
                        "{method} was refused with HTTP {status}: {}",
                        first_line(&body)
                    ));
                }
                Err(transport) => last = transport,
            }
            if attempt < ATTEMPTS {
                // The one sleep in the workspace. Master anti-goal 7 bans
                // threads, channels and async; `thread::sleep` spawns nothing
                // and blocks the caller, which is the whole of what a backoff
                // is. `docs/handoff/S25-block.md` records it.
                std::thread::sleep(std::time::Duration::from_millis(wait));
                wait *= 2;
            }
        }
        Err(format!("{method} failed {ATTEMPTS} times, last: {last}"))
    }
}

/// The canonical request body for one call.
///
/// `id` is a literal 1, not a counter: the body is the cache key, so a counter
/// would give one logical request a different name on every run and the cache
/// would never hit.
/// `pub(crate)` for the recorder's own tests, which seed a cache directory by
/// the same key `call` reads it with.
pub(crate) fn request_body(method: &str, params: &Value) -> String {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    serde_json::to_string(&body).expect("a JSON-RPC request encodes")
}

/// The `result` member, or the error the server named.
fn decode(method: &str, body: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(body)
        .map_err(|e| format!("the {method} response is not JSON: {e}"))?;
    if let Some(error) = value.get("error") {
        return Err(format!("{method} returned an error: {error}"));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| format!("the {method} response carries no result"))
}

/// POST `body` to `endpoint`, returning the HTTP status and the response body.
///
/// `-w '%{http_code}'` appends exactly three digits to stdout after the body, so
/// the split is the last three bytes and needs no parsing of the body itself.
/// `-s` silences the progress meter, `-S` keeps errors on stderr.
fn post(endpoint: &str, body: &str) -> Result<(u32, String), String> {
    let mut child = Command::new("curl")
        .arg("-sS")
        .arg("--max-time")
        .arg(TIMEOUT_SECONDS.to_string())
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("content-type: application/json")
        .arg("--data-binary")
        .arg("@-")
        .arg("-w")
        .arg("%{http_code}")
        .arg(endpoint)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("curl's stdin was piped");
        stdin
            .write_all(body.as_bytes())
            .map_err(|e| format!("cannot write the request to curl: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("curl did not finish: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl exited {}: {}",
            out.status.code().unwrap_or(-1),
            first_line(&String::from_utf8_lossy(&out.stderr))
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if stdout.len() < 3 {
        return Err("curl wrote no status code".to_string());
    }
    let split = stdout.len() - 3;
    let status: u32 = stdout[split..]
        .parse()
        .map_err(|_| format!("curl's status code is not a number: {:?}", &stdout[split..]))?;
    Ok((status, stdout[..split].to_string()))
}

/// The first line of a message, for an error that must stay one line.
fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or("").trim();
    if line.chars().count() > 200 {
        // By characters, not bytes: slicing a UTF-8 string at byte 200 can land
        // inside a code point and panic, and an error message is the last place
        // that should be able to.
        format!("{}…", line.chars().take(200).collect::<String>())
    } else {
        line.to_string()
    }
}

/// The content address of a request: the SHA-256 of its bytes, in hex.
///
/// SHA-256 and not Poseidon2, which the workspace also owns: this digest is a
/// *file name*, nothing about it is load-bearing for soundness, and a name a
/// developer can check against `shasum` from the shell is worth more here than
/// one only this repository can compute. Poseidon2's tags are the protocol's
/// and a cache key has no business in that namespace.
pub fn digest_hex(bytes: &[u8]) -> String {
    test_support::to_hex(&test_support::sha256(bytes))
}

/// A hex quantity (`0x1a`) as a `u64`.
pub fn u64_of(value: &Value, what: &str) -> Result<u64, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{what} is not a string: {value}"))?;
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("{what} is not a hex quantity: {text}"))?;
    u64::from_str_radix(digits, 16).map_err(|e| format!("{what} is not a u64: {text}: {e}"))
}

/// A hex quantity as a `u128`.
pub fn u128_of(value: &Value, what: &str) -> Result<u128, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{what} is not a string: {value}"))?;
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("{what} is not a hex quantity: {text}"))?;
    u128::from_str_radix(digits, 16).map_err(|e| format!("{what} is not a u128: {text}: {e}"))
}

/// A hex quantity or hex data as a big-endian 32-byte word, left-padded.
pub fn word_of(value: &Value, what: &str) -> Result<[u8; 32], String> {
    let bytes = bytes_of(value, what)?;
    if bytes.len() > 32 {
        return Err(format!("{what} is longer than 32 bytes"));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

/// Exactly 20 bytes of hex data.
pub fn address_of(value: &Value, what: &str) -> Result<[u8; 20], String> {
    let bytes = bytes_of(value, what)?;
    let out: [u8; 20] = bytes
        .try_into()
        .map_err(|_| format!("{what} is not 20 bytes"))?;
    Ok(out)
}

/// A `0x`-prefixed hex string as bytes.
///
/// An odd digit count is accepted for a *quantity* (`0x1a2`), which is how JSON-RPC
/// writes numbers, and is left-padded to a whole byte. Data (`0x00ff`) always has
/// an even count, so the two spellings do not collide.
pub fn bytes_of(value: &Value, what: &str) -> Result<Vec<u8>, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{what} is not a string: {value}"))?;
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("{what} is not 0x-prefixed: {text}"))?;
    let padded;
    let digits = if digits.len() % 2 == 1 {
        padded = format!("0{digits}");
        padded.as_str()
    } else {
        digits
    };
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_bytes().chunks(2) {
        let hi = hex_digit(pair[0]).ok_or_else(|| format!("{what} is not hex: {text}"))?;
        let lo = hex_digit(pair[1]).ok_or_else(|| format!("{what} is not hex: {text}"))?;
        out.push(hi * 16 + lo);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A `0x`-prefixed hex string for a byte slice, as JSON-RPC writes data.
pub fn hex_data(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A `0x`-prefixed hex quantity for a number, as JSON-RPC writes one: no
/// leading zeros, and `0x0` for zero.
pub fn hex_quantity(value: u64) -> String {
    format!("{value:#x}")
}

/// The cache directory a fixture set keeps its RPC snapshot in.
pub fn cache_dir(fixtures: &Path) -> PathBuf {
    fixtures.join("rpc-cache")
}
