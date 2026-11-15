//! CAL through ce-net-proto's JSON api (`cal::api::call`): compile and sign grants, check a use.
use ce_net_proto::cal::api::call;
use serde_json::{json, Value};

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

pub struct Verdict {
    pub allowed: bool,
    pub reason: String,
    pub text: String,
}

fn run(op: &str, req: Value) -> Result<Value, String> {
    let v: Value = serde_json::from_str(&call(op, &req.to_string())).map_err(|e| e.to_string())?;
    if v["ok"] == json!(true) {
        Ok(v)
    } else {
        Err(format!("CAL {op}: {}", v["error"]["message"].as_str().unwrap_or(&v.to_string())))
    }
}

/// Compiles CAL source against the ref book and signs every link with the given key files (`ed25519:<seed hex>`).
/// Returns (token hex, link ids, program ids).
pub fn mint(source: &str, refs: &Value, keys: &[String]) -> Result<(String, Vec<String>, Vec<String>), String> {
    let c = run("compile", json!({"source": source, "refs": refs, "now": now()}))?;
    let mut draft = c["draft"].clone();
    let mut token = String::new();
    for k in keys {
        let s = run("sign", json!({"draft": draft, "key": k}))?;
        draft = s["draft"].clone();
        token = s["token"].as_str().unwrap_or("").to_string();
    }
    if token.is_empty() {
        return Err("not every link is signed".into());
    }
    let ids = |k: &str| c[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    Ok((token, ids("ids"), ids("programs")))
}

/// What `ce-cal compile` answers for this source (the refusal text when it refuses).
pub fn compile_text(source: &str, refs: &Value) -> Result<(), String> {
    run("compile", json!({"source": source, "refs": refs, "now": now()})).map(|_| ())
}

pub fn explain(token: &str, refs: &Value) -> String {
    run("explain", json!({"token": token, "refs": refs})).map(|v| v["text"].as_str().unwrap_or("").to_string()).unwrap_or_else(|e| e)
}

fn verdict(v: Value) -> Verdict {
    Verdict { allowed: v["allowed"] == json!(true), reason: v["reason"].as_str().unwrap_or("").into(), text: v["text"].as_str().unwrap_or("").into() }
}

pub fn check_do(token: &str, node: &str, as_: &str, ability: &str, refs: &Value) -> Result<Verdict, String> {
    run("check", json!({"token": token, "node": node, "as": as_, "do": ability, "refs": refs})).map(verdict)
}

pub fn check_step(token: &str, node: &str, as_: &str, program: &str, step: u32, content: &[u8], refs: &Value) -> Result<Verdict, String> {
    let mut r = json!({"token": token, "node": node, "as": as_, "program": program, "step": step, "refs": refs});
    if !content.is_empty() {
        r["content"] = json!(hex::encode(content));
    }
    run("check", r).map(verdict)
}
