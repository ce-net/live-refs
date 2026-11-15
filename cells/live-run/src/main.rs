//! `live-refs-live --out proof`: the walk against the real ref cells on this node, through its door. Every call is a
//! typed ce_wire call with this node's own capability proof; each is recorded as a signed Step.
use refs_wire::{ref_graph as rg, ref_pin as rp, ref_resolve as rr};
use serde_json::{json, Value};
use std::time::Instant;

const DOOR: &str = "127.0.0.1:7700";

struct Run { log: live_proof::Log, key: ed25519_dalek::SigningKey, node: String, ms: Vec<f64> }

impl Run {
    fn rec(&mut self, step: u32, cell: &str, op: &str, req: Value, resp: Value, ms: f64, note: &str) -> Value {
        let (req, resp) = (scrub(&req), scrub(&resp));
        let s = resp.to_string();
        let verdict = if s.contains("\"Refused\"") || s.contains("\"Ambiguous\"") || s.contains("\"Err\"") || s.contains("\"Unknown\"") || s.contains("\"error\"") { "refused" } else { "ok" };
        let st = live_proof::Step { n: 0, step, cell: cell.into(), op: op.into(), node: self.node.clone(), to: self.node.clone(),
            request_ref: format!("ce-blob:sha256:{}", live_proof::sha256_hex(req.to_string().as_bytes())), response_sha256: live_proof::sha256_hex(s.as_bytes()),
            ms, verdict: verdict.into(), request: req, response: json!({"body": resp}), note: note.into(), prev: String::new(), key: String::new(), sig: String::new() };
        self.log.push(st, &self.key);
        resp
    }
}

/// The published proof names only public things: this machine is "ops-1", private repositories and cells are
/// "(private)", and evidence lines from private checkouts are dropped (their count stays).
fn scrub(v: &Value) -> Value {
    const PUBLIC: [&str; 4] = ["live-refs", "ce-net-proto", "demos", "ce-ref-id"];
    let host = std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string();
    let w = |s: &str| -> String {
        let home = std::env::var("HOME").unwrap_or_default();
        let s = s.replace(&host, "ops-1").replace(&home, "~");
        let mut out = String::new();
        for (i, part) in s.split("repo:").enumerate() {
            if i == 0 { out.push_str(part); continue; }
            let name: String = part.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
            if PUBLIC.contains(&name.as_str()) { out.push_str("repo:"); out.push_str(part); } else { out.push_str("repo:(private)"); out.push_str(&part[name.len()..]); }
        }
        out
    };
    match v {
        Value::String(s) => Value::String(w(s)),
        Value::Array(a) => Value::Array(a.iter().map(scrub).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| {
            if k == "evidence" { return (k.clone(), json!("(evidence line on ops-1)")); }
            if k == "from" || k == "to" { if let Some(t) = x.as_str() { if t.starts_with("api:") || t.starts_with("repo:") { let n = t.splitn(2, ':').nth(1).unwrap_or(""); if !PUBLIC.contains(&n) { return (k.clone(), json!(format!("{}:(private)", &t[..t.find(':').unwrap()]))); } } } }
            if k == "why" { return (k.clone(), json!(x.as_str().unwrap_or("").split(':').next().unwrap_or(""))); }
            (k.clone(), scrub(x))
        }).collect()),
        o => o.clone(),
    }
}

async fn client<A: ce_wire::Api>() -> (ce_wire::Client<A>, f64) {
    let t = Instant::now();
    let tok = ce_gate::self_proof::<A>(300).expect("self proof");
    let c = ce_wire::Client::<A>::connect_opts(DOOR, tok, true, std::time::Duration::from_secs(20)).await.unwrap_or_else(|e| panic!("{}: {e:?}", A::NAME));
    (c, t.elapsed().as_secs_f64() * 1000.0)
}

macro_rules! call { ($run:expr, $step:expr, $c:expr, $op:ty, $req:expr, $note:expr) => {{
    let req = $req;
    let t = Instant::now();
    let r = $c.call::<$op>(&req).await;
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    let v = match r { Ok(x) => serde_json::to_value(x).unwrap(), Err(e) => json!({"error": format!("{e:?}")}) };
    let api = <<$op as ce_wire::Op>::Api as ce_wire::Api>::NAME;
    $run.ms.push(ms);
    ($run.rec($step, api, <$op as ce_wire::Op>::NAME, serde_json::to_value(&req).unwrap(), v, ms, $note), ms)
}} }

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let out = std::path::PathBuf::from(a.iter().position(|x| x == "--out").and_then(|i| a.get(i + 1)).cloned().unwrap_or("proof".into()));
    let t_all = Instant::now();
    let mut seed = [0u8; 32];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut seed).unwrap();
    let node = std::fs::read_to_string("/etc/hostname").unwrap().trim().to_string();
    let mut run = Run { log: Default::default(), key: ed25519_dalek::SigningKey::from_bytes(&seed), node: "ops-1".into(), ms: vec![] };
    let mut nums = serde_json::Map::new();

    // 1. the cells, started by the door from their cell.toml on first call
    let (res, c1) = client::<rr::RefResolve>().await;
    let (pin, c2) = client::<rp::RefPin>().await;
    let (graph, c3) = client::<rg::RefGraph>().await;
    nums.insert("connect_ms".into(), json!({"ref.resolve": c1, "ref.pin": c2, "ref.graph": c3}));
    for _ in 0..1 {
        call!(run, 1, res, rr::HealthOp, (), "ref.resolve health");
        call!(run, 1, pin, rp::HealthOp, (), "ref.pin health");
        call!(run, 1, graph, rg::HealthOp, (), "ref.graph health");
    }

    // 2. kinds this node can check itself
    let head = String::from_utf8(std::process::Command::new("git").args(["-C", &format!("{}/dev/live-refs", std::env::var("HOME").unwrap()), "rev-parse", "--short=7", "HEAD"]).output().unwrap().stdout).unwrap().trim().to_string();
    let repo_at = format!("repo:live-refs/README.md@{head}");
    let mut kinds = vec![];
    for r in [repo_at.clone(), format!("node:{node}"), "cell:ref.extract@1".into(), "cell:ref.pin@1#Fetch".into()] {
        let (v, ms) = call!(run, 2, res, rr::Resolve, rr::ResolveReq { reference: r.clone() }, "resolved on this node");
        kinds.push(json!({"ref": r, "located": v["Ok"]["Located"].is_object(), "ms": ms}));
    }
    // a blob, put into ref.pin and announced into the index
    let bytes = format!("live-refs on {node} at {}", t_all.elapsed().as_nanos()).into_bytes();
    let blob = ce_ref_id::blob_ref(&bytes).id();
    call!(run, 2, pin, rp::Put, rp::PutReq { id: blob.clone(), bytes: bytes.clone() }, "hold a blob");
    call!(run, 2, res, rr::Publish, rr::Announce { id: blob.clone(), kind: "blob".into(), node: node.clone(), sha256: Some(ce_ref_id::sha256_hex(&bytes)), size: bytes.len() as u64,
        at_ms: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64, gone: false, detail: "put by live-refs-live".into() }, "announce it");
    let (v, ms) = call!(run, 2, res, rr::Resolve, rr::ResolveReq { reference: blob.clone() }, "the blob, from the index");
    kinds.push(json!({"ref": blob, "located": v["Ok"]["Located"].is_object(), "ms": ms}));
    nums.insert("kinds".into(), json!(kinds));

    // 3. pin a real repo file at a commit; hold a file, change one byte, Fetch refuses
    let (p, _) = call!(run, 3, pin, rp::Pin, rp::PinReq { reference: repo_at.clone() }, "pin a real checkout file at a commit");
    let pinned_repo = p["Ok"]["reference"].as_str().unwrap_or("").to_string();
    let (f0, _) = call!(run, 3, pin, rp::Fetch, rp::FetchReq { pinned: pinned_repo.clone() }, "the pinned bytes");
    let fid = ce_ref_id::file_ref("https://github.com/ce-net/live-refs", "notes/plan.md").unwrap().id();
    let (p1, _) = call!(run, 3, pin, rp::Put, rp::PutReq { id: fid.clone(), bytes: b"# Q4 plan\n".to_vec() }, "hold a file");
    let pinned = p1["Ok"]["reference"].as_str().unwrap_or("").to_string();
    call!(run, 3, pin, rp::Put, rp::PutReq { id: fid.clone(), bytes: b"# Q5 plan\n".to_vec() }, "one byte changes");
    let (f1, _) = call!(run, 3, pin, rp::Fetch, rp::FetchReq { pinned: pinned.clone() }, "the old pin is refused");
    nums.insert("pin".into(), json!({"repo_file": pinned_repo, "repo_fetch_ok": f0["Ok"]["Ok"].is_object(), "tamper_refused": f1["Ok"]["Refused"].is_object()}));

    // 4. ambiguity on a real node
    let (amb, _) = call!(run, 4, res, rr::Resolve, rr::ResolveReq { reference: "README.md".into() }, "a bare name on a real node");
    let first = pinned_repo.clone();
    let (ok, _) = call!(run, 4, res, rr::Resolve, rr::ResolveReq { reference: first.clone() }, "one pinned candidate");
    nums.insert("ambiguity".into(), json!({"refused": amb["Ok"]["Ambiguous"].is_object(), "reason": amb["Ok"]["Ambiguous"]["reason"], "accepted": ok["Ok"]["Located"].is_object(), "pinned": first}));

    // 5. the graph over the live ref.extract
    let (g, _) = call!(run, 5, graph, rg::Links, rg::LinksReq { reference: "cell:ref.index@1".into(), dir: rg::Dir::Both, depth: 1 }, "what links to ref.index, from ref.extract");
    nums.insert("graph".into(), json!({"edges": g["Ok"].as_array().map(|a| a.len()).unwrap_or(0)}));

    let mut s = run.ms.clone();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    nums.insert("call_ms".into(), json!({"n": s.len(), "p50": s[s.len() / 2], "max": s[s.len() - 1]}));
    nums.insert("node".into(), json!("ops-1"));
    let mut nums: serde_json::Map<String, Value> = scrub(&Value::Object(nums)).as_object().unwrap().clone();
    nums.insert("total_ms".into(), json!(t_all.elapsed().as_secs_f64() * 1000.0));
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("live.jsonl"), run.log.jsonl()).unwrap();
    std::fs::write(out.join("live-summary.json"), serde_json::to_string_pretty(&Value::Object(nums.clone())).unwrap() + "\n").unwrap();
    println!("{}", serde_json::to_string_pretty(&Value::Object(nums)).unwrap());
}
