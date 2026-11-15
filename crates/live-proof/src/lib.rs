//! `Step{n, cell, op, node, request_ref, response_sha256, ms, verdict}`, signed by the node that answered.
//! A run is `proof/run.jsonl`: one JSON object per line, each with `sig` (ed25519 over the canonical JSON of
//! the step without `sig`) and `key` (the signer's public key). `verify` checks every line and the chain
//! (`prev` is the sha256 of the line before), so a dropped or edited step is found.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Step {
    pub n: u32,
    /// Which step of the walk (1..8) this call belongs to.
    pub step: u32,
    pub cell: String,
    pub op: String,
    /// The node that made the call, and the node that answered it.
    pub node: String,
    pub to: String,
    /// `ce-blob:sha256:<hash>` of the request body as sent.
    pub request_ref: String,
    pub response_sha256: String,
    pub ms: f64,
    /// "ok", "refused" or "error".
    pub verdict: String,
    /// The request and the answer, as sent and returned (small, so the page can show them verbatim).
    pub request: serde_json::Value,
    pub response: serde_json::Value,
    pub note: String,
    pub prev: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub sig: String,
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn body(s: &Step) -> Vec<u8> {
    let mut c = s.clone();
    c.sig.clear();
    serde_json::to_vec(&c).unwrap()
}

pub fn sign(s: &mut Step, k: &SigningKey) {
    s.key = format!("ed25519:{}", hex::encode(k.verifying_key().to_bytes()));
    s.sig = String::new();
    s.sig = hex::encode(k.sign(&body(s)).to_bytes());
}

pub fn check(s: &Step) -> Result<(), String> {
    let kh = s.key.strip_prefix("ed25519:").ok_or("no key")?;
    let kb: [u8; 32] = hex::decode(kh).map_err(|e| e.to_string())?.try_into().map_err(|_| "key length")?;
    let vk = VerifyingKey::from_bytes(&kb).map_err(|e| e.to_string())?;
    let sb: [u8; 64] = hex::decode(&s.sig).map_err(|e| e.to_string())?.try_into().map_err(|_| "sig length")?;
    vk.verify(&body(s), &Signature::from_bytes(&sb)).map_err(|e| format!("step {}: bad signature: {e}", s.n))
}

/// Appends steps; each line's `prev` is the sha256 of the previous line.
pub struct Log {
    pub steps: Vec<Step>,
    last: String,
}
impl Default for Log {
    fn default() -> Self {
        Log { steps: vec![], last: "0".repeat(64) }
    }
}
impl Log {
    pub fn push(&mut self, mut s: Step, k: &SigningKey) -> &Step {
        s.n = self.steps.len() as u32 + 1;
        s.prev = self.last.clone();
        sign(&mut s, k);
        self.last = sha256_hex(serde_json::to_string(&s).unwrap().as_bytes());
        self.steps.push(s);
        self.steps.last().unwrap()
    }
    pub fn jsonl(&self) -> String {
        self.steps.iter().map(|s| serde_json::to_string(s).unwrap() + "\n").collect()
    }
}

/// Checks every signature and the chain. Returns the number of steps; `keys` (if not empty) are the only signers accepted.
pub fn verify(jsonl: &str, keys: &[String]) -> Result<usize, String> {
    let mut prev = "0".repeat(64);
    let mut n = 0;
    for (i, line) in jsonl.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let s: Step = serde_json::from_str(line).map_err(|e| format!("line {}: {e}", i + 1))?;
        check(&s)?;
        if s.prev != prev {
            return Err(format!("step {}: chain broken (a step before it was changed or dropped)", s.n));
        }
        if !keys.is_empty() && !keys.contains(&s.key) {
            return Err(format!("step {}: signed by {} which is not a node of this run", s.n, s.key));
        }
        prev = sha256_hex(line.as_bytes());
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn step() -> Step {
        Step { n: 0, step: 1, cell: "ref.pin".into(), op: "Fetch".into(), node: "a".into(), to: "b".into(), request_ref: "ce-blob:sha256:00".into(),
            response_sha256: "11".into(), ms: 1.5, verdict: "refused".into(), request: serde_json::json!({}), response: serde_json::json!({"Refused": {}}),
            note: String::new(), prev: String::new(), key: String::new(), sig: String::new() }
    }
    #[test]
    fn signed_chain_verifies_and_edits_are_found() {
        let k = SigningKey::from_bytes(&[7; 32]);
        let mut log = Log::default();
        log.push(step(), &k);
        log.push(step(), &k);
        let j = log.jsonl();
        assert_eq!(verify(&j, &[]), Ok(2));
        let edited = j.replacen("\"refused\"", "\"ok\"", 1);
        assert!(verify(&edited, &[]).is_err());
        let dropped: String = j.lines().skip(1).map(|l| l.to_string() + "\n").collect();
        assert!(verify(&dropped, &[]).unwrap_err().contains("chain"));
    }
}
