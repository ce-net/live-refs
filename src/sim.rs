//! `live-refs sim`: four devices as four processes on this machine, and the eight steps of the walk.
//! Everything a step shows is a real call between two of those processes, signed by both, and appended to
//! proof/run.jsonl as a signed Step.

use crate::cal;
use ce_ref_id::Ref;
use live_proof::{Log, Step};
use serde_json::{json, Value};
use sim_mesh::{key_hex, new_key, Controller, Member, Mesh, Roster};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const NODES: [&str; 4] = ["laptop", "server", "enterprise", "phone"];
const NOTES: &str = "https://github.com/leif-rydenfalk/notes";
const HUEY: &str = "https://github.com/example/huey-scripts";
const SCANS: &str = "https://github.com/leif-rydenfalk/scans";
const C_NOTES: &str = "7c1e2d4a9b3f5e6d8c0a1b2c3d4e5f6a7b8c9d0e";
const C_HUEY: &str = "3f2a1c7e9d4b5a6c8e0f1a2b3c4d5e6f7a8b9c0d";
const C_SCANS: &str = "a41b9e02c7d35f6e8a9b0c1d2e3f4a5b6c7d8e9f";

pub struct Run {
    pub ctl: Controller,
    pub log: Log,
    pub root: ed25519_dalek::SigningKey,
    pub resolve_ms: Vec<f64>,
    pub nums: BTreeMap<String, Value>,
    pub dir: PathBuf,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn seed(k: &ed25519_dalek::SigningKey) -> String {
    format!("ed25519:{}", hex::encode(k.to_bytes()))
}

/// The verdict of an answer as the page shows it.
fn verdict_of(body: &Value, refused: &Option<String>) -> &'static str {
    let s = body.to_string();
    if refused.is_some() {
        "refused"
    } else if s.contains("\"Refused\"") || s.contains("\"Ambiguous\"") || s.contains("\"Err\"") || s.contains("\"Unknown\"") {
        "refused"
    } else {
        "ok"
    }
}

impl Run {
    /// One call made by node `from` to node `to`, recorded as a signed Step. Returns the answer body and the ms.
    pub fn call(&mut self, step: u32, from: &str, to: &str, api: &str, op: &str, body: Value, note: &str) -> (Value, f64) {
        let r = self.ctl.ctl(from, "Call", json!({"to": to, "api": api, "op": op, "body": body})).expect("ctl");
        let ms = r.body["ms"].as_f64().unwrap_or(0.0);
        let (resp, verdict, sig, rnode) = match r.body.get("reply") {
            Some(rep) => {
                let refused: Option<String> = serde_json::from_value(rep["refused"].clone()).unwrap_or(None);
                let b = if let Some(x) = &refused { json!({"refused": x}) } else { rep["body"].clone() };
                (b.clone(), verdict_of(&b, &refused), rep["sig"].as_str().unwrap_or("").to_string(), rep["node"].as_str().unwrap_or("").to_string())
            }
            None => (json!({"transport": r.body["error"]}), "refused", String::new(), String::new()),
        };
        let req_bytes = body.to_string();
        let s = Step {
            n: 0, step, cell: api.into(), op: op.into(), node: from.into(), to: to.into(),
            request_ref: format!("ce-blob:sha256:{}", live_proof::sha256_hex(req_bytes.as_bytes())),
            response_sha256: live_proof::sha256_hex(resp.to_string().as_bytes()),
            ms, verdict: verdict.into(), request: body, response: json!({"body": resp, "node": rnode, "sig": sig}), note: note.into(),
            prev: String::new(), key: String::new(), sig: String::new(),
        };
        self.log.push(s, &self.root);
        if op == "Resolve" {
            self.resolve_ms.push(ms);
        }
        (resp, ms)
    }

    /// A step that is not a mesh call (a CAL compile on one node), recorded the same way.
    fn local(&mut self, step: u32, node: &str, cell: &str, op: &str, req: Value, resp: Value, ok: bool, ms: f64, note: &str) {
        let s = Step {
            n: 0, step, cell: cell.into(), op: op.into(), node: node.into(), to: node.into(),
            request_ref: format!("ce-blob:sha256:{}", live_proof::sha256_hex(req.to_string().as_bytes())),
            response_sha256: live_proof::sha256_hex(resp.to_string().as_bytes()), ms,
            verdict: if ok { "ok" } else { "refused" }.into(), request: req, response: json!({"body": resp}), note: note.into(),
            prev: String::new(), key: String::new(), sig: String::new(),
        };
        self.log.push(s, &self.root);
    }

    fn ctl(&self, node: &str, op: &str, body: Value) -> Value {
        let r = self.ctl.ctl(node, op, body).expect("ctl");
        if let Some(e) = r.refused {
            panic!("{node} {op}: {e}");
        }
        r.body
    }

    fn resolve_quiet(&mut self, from: &str, reference: &str) -> (Value, f64) {
        let r = self.ctl.ctl(from, "Call", json!({"to": from, "api": "ref.resolve", "op": "Resolve", "body": {"reference": reference}})).unwrap();
        let ms = r.body["ms"].as_f64().unwrap_or(0.0);
        (r.body["reply"]["body"].clone(), ms)
    }
}

fn holders(v: &Value) -> Vec<String> {
    v["Ok"]["Located"]["holders"].as_array().map(|a| a.iter().map(|h| h["node"].as_str().unwrap().to_string()).collect()).unwrap_or_default()
}

fn pct(v: &[f64], p: f64) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if s.is_empty() {
        return 0.0;
    }
    let i = ((p / 100.0) * (s.len() as f64 - 1.0)).round() as usize;
    (s[i] * 100.0).round() / 100.0
}

fn ensure_erp_legacy() {
    let exe = std::env::current_exe().unwrap().with_file_name("erp-legacy");
    if exe.exists() {
        return;
    }
    // A fresh clone: `cargo run` built only this binary. The order system is its own program; build it once.
    eprintln!("building erp-legacy (the ordinary order system that erp.orders@1 wraps) ...");
    let release = exe.parent().is_some_and(|p| p.ends_with("release"));
    let mut c = std::process::Command::new(std::env::var("CARGO").unwrap_or("cargo".into()));
    c.args(["build", "-q", "--bin", "erp-legacy"]);
    if release {
        c.arg("--release");
    }
    let st = c.status().expect("cargo");
    assert!(st.success() && exe.exists(), "could not build erp-legacy");
}

pub fn sim(out: &Path) -> Result<(), String> {
    let t_all = Instant::now();
    ensure_erp_legacy();
    let dir = std::env::temp_dir().join(format!("live-refs-run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // ---------------------------------------------------------------- keys, roster, ref book, grants
    let root = new_key();
    let keys: BTreeMap<&str, _> = NODES.iter().map(|n| (*n, new_key())).collect();
    let (indexer, reporter) = (new_key(), new_key());
    let mut roster = Roster { root: key_hex(&root), nodes: BTreeMap::new() };
    for n in NODES {
        roster.nodes.insert(n.into(), Member { port: free_port(), key: key_hex(&keys[n]) });
    }
    std::fs::write(dir.join("roster.json"), serde_json::to_vec_pretty(&roster).unwrap()).unwrap();

    let files: Vec<(&str, &str, &str, &str, &str, Vec<u8>)> = vec![
        // (node, repo name, origin, path, commit, bytes)
        ("laptop", "notes", NOTES, "plan.md", C_NOTES, b"# Q4 plan\nShip the order report. Owner: person:leif\n".to_vec()),
        ("laptop", "notes", NOTES, "run.py", C_NOTES, b"print('notes: tidy the inbox')\n".to_vec()),
        ("laptop", "notes", NOTES, "reports/q4.py", C_NOTES, b"# reads row:refs.catalog/asset-7, then asks erp.orders for its order\norder = erp.GetOrder('SO-1002')\n".to_vec()),
        ("server", "huey-scripts", HUEY, "run.py", C_HUEY, b"print('huey: rotate the logs')\n".to_vec()),
        ("phone", "scans", SCANS, "invoices/SO-1002.pdf", C_SCANS, b"%PDF-1.4 invoice SO-1002 Umea Robotics 485.00 EUR\n".to_vec()),
    ];
    let pid = |origin: &str, path: &str| ce_ref_id::file_ref(origin, path).unwrap().id();
    let img = b"\xff\xd8\xff\xe0 IMG_0042 phone camera, receipt photo\n".to_vec();
    let img_sha = ce_ref_id::sha256_hex(&img);
    let pk = |k: &ed25519_dalek::SigningKey| format!("ed25519:{}", key_hex(k));
    let mut refbook = json!({
        "principals": {"person:leif": [pk(&root)], "agent:indexer": [pk(&indexer)], "agent:reporter": [pk(&reporter)]},
        "nodes": {}, "repos": {"notes": [NOTES], "huey-scripts": [HUEY], "scans": [SCANS]},
        "files": {}, "blobs": {img_sha.clone(): img.len()}, "cells": {"erp.orders@1": [pk(&keys["enterprise"])]}, "roots": ["person:leif"]
    });
    for n in NODES {
        refbook["nodes"][n] = json!([key_hex(&keys[n])]);
    }
    for (_, _, origin, path, commit, bytes) in &files {
        refbook["files"][pid(origin, path)] = json!([{"sha256": ce_ref_id::sha256_hex(bytes), "size": bytes.len(), "commit": commit}]);
    }

    // Membership: Leif's root key grants each node the rights of the ref cells, on any node of this mesh.
    let rights = "ref.resolve:health, ref.resolve:read, ref.resolve:announce, ref.pin:health, ref.pin:read, ref.pin:write, ref.graph:read, ref.graph:write, refs.catalog:read, refs.catalog:write";
    let mut membership = json!({});
    let mut membership_src = String::new();
    for (i, n) in NODES.iter().enumerate() {
        let src = format!("cal 1\nperson:leif grants node:{n} {{\n  can {rights}\n  on any node\n  for 30d\n  nonce {}\n}}\n", 100 + i);
        let (tok, _, _) = cal::mint(&src, &refbook, &[seed(&root)])?;
        membership[*n] = json!(tok);
        if i == 0 {
            membership_src = src;
        }
    }
    // The grant of step 4: the reporter agent may run one pinned report on node:enterprise, which asks erp.orders.
    let q4 = &files[2];
    let q4_sha = ce_ref_id::sha256_hex(&q4.5);
    let get_body = json!({"id": "SO-1002"});
    let grant_src = format!(
        "cal 1\nperson:leif grants agent:reporter {{\n  can erp.orders:GetOrder, proc.spawn:run\n  on node:enterprise\n  for 30d\n  only {{\n    spawn repo:notes/reports/q4.py@{} sha256:{q4_sha} at /srv/reports/q4.py on node:enterprise\n    call cell:erp.orders@1 GetOrder on node:enterprise body sha256:{}\n  }}\n  nonce 7\n}}\n",
        &C_NOTES[..7], live_proof::sha256_hex(get_body.to_string().as_bytes()));
    let (grant, grant_ids, grant_programs) = cal::mint(&grant_src, &refbook, &[seed(&root)])?;
    let grant_id = grant_ids[0].clone();
    let program = grant_programs[0].clone();
    let book = json!({"refs": refbook, "membership": membership});
    std::fs::write(dir.join("book.json"), serde_json::to_vec_pretty(&book).unwrap()).unwrap();

    for n in NODES {
        let d = dir.join(n);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("me.json"), json!({"name": n, "seed": hex::encode(keys[n].to_bytes())}).to_string()).unwrap();
    }

    // ---------------------------------------------------------------- start the four nodes
    let exe = std::env::current_exe().unwrap();
    let dir2 = dir.clone();
    let ctl = Controller {
        mesh: Mesh::new("controller", root.clone(), roster.clone()),
        children: Mutex::new(BTreeMap::new()),
        spawn: Box::new(move |name| std::process::Command::new(&exe).arg("node").arg(dir2.join(name)).spawn().expect("spawn node")),
    };
    let mut up_ms = BTreeMap::new();
    for n in NODES {
        ctl.start(n);
    }
    for n in NODES {
        up_ms.insert(n, ctl.wait_up(n, Duration::from_secs(20))?.as_secs_f64() * 1000.0);
    }
    let mut run = Run { ctl, log: Log::default(), root: root.clone(), resolve_ms: vec![], nums: BTreeMap::new(), dir: dir.clone() };
    let erp = run.ctl("enterprise", "StartErp", Value::Null);
    let erp_sha = erp["binary_sha256"].as_str().unwrap().to_string();

    // What each device holds, announced to the mesh.
    for (node, repo, origin, path, commit, bytes) in &files {
        run.ctl(node, "Put", json!({"id": pid(origin, path), "written": format!("repo:{repo}/{path}@{}", &commit[..7]), "commit": commit, "kind": "file", "bytes": bytes}));
    }
    let img_id = format!("ce-blob:sha256:{img_sha}");
    run.ctl("phone", "Put", json!({"id": img_id, "written": img_id, "kind": "blob", "bytes": img}));
    let ann = |id: &str, kind: &str, detail: String| json!({"id": id, "kind": kind, "node": "", "sha256": null, "size": 0, "at_ms": 0, "gone": false, "detail": detail});
    for n in ["laptop", "phone"] {
        run.ctl(n, "Announce", ann("person:leif", "person", format!("{} | signed in on this device", pk(&root))));
    }
    run.ctl("server", "Announce", ann("agent:indexer", "agent", format!("{} | runs ref.extract scans", pk(&indexer))));
    run.ctl("server", "Announce", ann("agent:reporter", "agent", format!("{} | runs reports", pk(&reporter))));
    let schemas: BTreeMap<String, String> = refs_api::contracts().into_iter().map(|(n, v, s, _)| (format!("{n}@{v}"), format!("{s:016x}"))).collect();
    for n in NODES {
        for c in ["ref.resolve@1", "ref.pin@1", "ref.graph@1", "refs.catalog@1"] {
            run.ctl(n, "Announce", ann(&format!("cell:{c}"), "cell", format!("schema {} | ed25519:{}", schemas[c], key_hex(&keys[n]))));
        }
    }
    run.ctl("enterprise", "Announce", ann("cell:erp.orders@1", "cell (wrapped system)", format!("wrapped from erp-legacy sha256:{erp_sha} (plain HTTP) | schema {} | ed25519:{}", schemas["erp.orders@1"], key_hex(&keys["enterprise"]))));
    run.ctl("enterprise", "Announce", ann(&format!("cap:{grant_id}"), "capability", format!("issued by person:leif {} to agent:reporter | can erp.orders:GetOrder, proc.spawn:run on node:enterprise | program {program}", pk(&root))));
    let q4_id = pid(NOTES, "reports/q4.py");
    let q4_pinned = format!("{q4_id} sha256:{q4_sha}");
    let row = "row:refs.catalog/asset-7".to_string();
    run.ctl("enterprise", "AddEdges", json!([
        {"from": format!("cap:{grant_id}"), "to": "cell:erp.orders@1#GetOrder", "why": "grant names op", "evidence": format!("CAL link {grant_id}: can erp.orders:GetOrder")},
        {"from": format!("cap:{grant_id}"), "to": q4_pinned, "why": "grant pins file", "evidence": format!("program {program} step 0: spawn ... sha256:{q4_sha}")},
        {"from": format!("cap:{grant_id}"), "to": "person:leif", "why": "issued by", "evidence": format!("CAL link {grant_id} issuer {}", pk(&root))},
        {"from": format!("cap:{grant_id}"), "to": "agent:reporter", "why": "granted to", "evidence": format!("CAL link {grant_id} audience {}", pk(&reporter))},
        {"from": q4_id, "to": row, "why": "reads row", "evidence": "repo:notes/reports/q4.py line 1"},
        {"from": q4_id, "to": format!("repo:notes/reports/q4.py@{}", &C_NOTES[..7]), "why": "at commit", "evidence": format!("observed at commit {C_NOTES}")},
    ]));

    let plan_id = pid(NOTES, "plan.md");
    let huey_sha = ce_ref_id::sha256_hex(&files[3].5);
    let huey_pinned = format!("repo:huey-scripts/run.py@{} sha256:{huey_sha}", &C_HUEY[..7]);
    let nine: Vec<(&str, String, &str)> = vec![
        ("file on a personal laptop", plan_id.clone(), "phone"),
        ("blob", img_id.clone(), "server"),
        ("repo path pinned at a commit", huey_pinned.clone(), "enterprise"),
        ("node", "node:enterprise".into(), "laptop"),
        ("person", "person:leif".into(), "enterprise"),
        ("agent", "agent:indexer".into(), "phone"),
        ("cell op", "cell:ref.pin@1#Fetch".into(), "laptop"),
        ("capability", format!("cap:{grant_id}"), "server"),
        ("enterprise system wrapped as a cell", "cell:erp.orders@1".into(), "phone"),
    ];

    // ---------------------------------------------------------------- 1. nine kinds, each resolved
    let mut resolved = 0;
    let mut cards = vec![];
    for (kind, r, from) in &nine {
        let (v, ms) = run.call(1, from, from, "ref.resolve", "Resolve", json!({"reference": r}), kind);
        if v["Ok"]["Located"].is_object() {
            resolved += 1;
        }
        cards.push(json!({"kind": kind, "ref": r, "from": from, "holders": holders(&v), "ms": ms, "located": v["Ok"]["Located"]}));
    }
    // More rounds for the latency numbers (not each one a step of the walk).
    for _ in 0..20 {
        for (_, r, from) in &nine {
            let (_, ms) = run.resolve_quiet(from, r);
            run.resolve_ms.push(ms);
        }
    }
    run.nums.insert("kinds_resolved".into(), json!(format!("{resolved} of 9")));

    // ---------------------------------------------------------------- 2. the file moves; the id stays
    let (before, _) = run.call(2, "phone", "phone", "ref.resolve", "Resolve", json!({"reference": plan_id}), "before the move");
    let t0 = Instant::now();
    let pulled = run.ctl("server", "Pull", json!({"id": plan_id, "from": "laptop", "kind": "file", "meta": [format!("repo:notes/plan.md@{}", &C_NOTES[..7]), C_NOTES]}));
    run.local(2, "server", "ref.pin", "Fetch", pulled["fetch"]["request"].clone(), json!({"pinned": pulled["pinned"], "from": "laptop", "sig": pulled["fetch"]["reply_sig"]}), true,
        pulled["fetch"]["ms"].as_f64().unwrap_or(0.0), "server pulls the pinned bytes from laptop");
    run.ctl("laptop", "Drop", json!({"id": plan_id, "kind": "file"}));
    let mut converged = false;
    let mut polls = 0;
    while t0.elapsed() < Duration::from_secs(10) {
        polls += 1;
        let all = NODES.iter().all(|n| holders(&run.resolve_quiet(n, &plan_id).0) == vec!["server".to_string()]);
        if all {
            converged = true;
            break;
        }
    }
    let conv_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let (after, _) = run.call(2, "phone", "phone", "ref.resolve", "Resolve", json!({"reference": plan_id}), "after the move");
    let same_id = before["Ok"]["Located"]["id"] == after["Ok"]["Located"]["id"];
    run.nums.insert("move".into(), json!({"converged": converged, "ms": (conv_ms * 10.0).round() / 10.0, "polls": polls, "same_id": same_id,
        "before": holders(&before), "after": holders(&after), "id": plan_id}));

    // ---------------------------------------------------------------- 3. pin, change one byte, Fetch refuses
    let (p, _) = run.call(3, "enterprise", "server", "ref.pin", "Pin", json!({"reference": plan_id}), "pin the moved file");
    let pinned = p["Ok"]["reference"].as_str().unwrap().to_string();
    let (f1, _) = run.call(3, "enterprise", "server", "ref.pin", "Fetch", json!({"pinned": pinned}), "pinned bytes, untouched");
    let tam = run.ctl("server", "Tamper", json!({"id": plan_id}));
    let (f2, _) = run.call(3, "enterprise", "server", "ref.pin", "Fetch", json!({"pinned": pinned}), "after one byte changed on server");
    let (v2, _) = run.call(3, "enterprise", "server", "ref.pin", "Verify", json!({"pinned": pinned}), "verify says the same");
    run.ctl("server", "Tamper", json!({"id": plan_id})); // the byte back, so later steps see the real file
    let mut tamper_refused = 0;
    if f2["Ok"]["Refused"].is_object() {
        tamper_refused += 1;
    }

    // ---------------------------------------------------------------- 4. a grant that names an op and a pinned file
    let order = |id: &str| json!({"id": id, "grant": grant, "program": program, "report": q4_pinned});
    let (g1, _) = run.call(4, "server", "enterprise", "erp.orders", "GetOrder", order("SO-1002"), "allowed: the report's hash matches the grant");
    let (g2, _) = run.call(4, "server", "enterprise", "erp.orders", "ListOrders", order("SO-1002"), "refused: another op");
    run.ctl("laptop", "Tamper", json!({"id": q4_id}));
    let (g3, _) = run.call(4, "server", "enterprise", "erp.orders", "GetOrder", order("SO-1002"), "refused: the report changed on laptop");
    run.ctl("laptop", "Tamper", json!({"id": q4_id}));
    if g3.to_string().contains("content hash mismatch") {
        tamper_refused += 1;
    }
    run.nums.insert("grant".into(), json!({
        "allowed": g1["Ok"].is_object(), "other_op_refused": g2.to_string().contains("does not grant"), "tampered_refused": g3.to_string().contains("content hash mismatch"),
        "link": grant_id, "program": program, "source": grant_src, "explain": cal::explain(&grant, &refbook)}));
    run.nums.insert("tamper_refusals".into(), json!(format!("{tamper_refused} of 2")));

    // ---------------------------------------------------------------- 5. a record on server points at a file on phone
    let inv = &files[4];
    let inv_id = pid(inv.2, inv.3);
    let inv_pinned = format!("{inv_id} sha256:{}", ce_ref_id::sha256_hex(&inv.5));
    let asset = json!({"id": "asset-7", "title": "Invoice SO-1002 (scan)", "file": inv_id, "pinned": inv_pinned, "owner": format!("person:leif {}", pk(&root))});
    run.call(5, "laptop", "server", "refs.catalog", "Insert", asset, "Leif's laptop writes the row on server");
    let (row_v, _) = run.call(5, "enterprise", "server", "refs.catalog", "Get", json!("asset-7"), "enterprise reads the row");
    let rp = row_v["Ok"]["pinned"].as_str().unwrap_or("").to_string();
    let (loc, _) = run.call(5, "enterprise", "enterprise", "ref.resolve", "Resolve", json!({"reference": rp}), "where the row's file lives now");
    let (fb, _) = run.call(5, "enterprise", "phone", "ref.pin", "Fetch", json!({"pinned": rp}), "the bytes, from phone, checked against the row's pin");
    run.ctl("enterprise", "AddEdges", json!([{"from": "node:enterprise", "to": row, "why": "read by", "evidence": "refs.catalog.Get asset-7 from node:enterprise"}]));
    run.nums.insert("record".into(), json!({"row_on": "server", "file_on": holders(&loc), "read_from": "enterprise", "bytes_ok": fb["Ok"]["Ok"].is_object()}));

    // ---------------------------------------------------------------- 6. the graph
    let (g, _) = run.call(6, "laptop", "server", "ref.graph", "Links", json!({"reference": row, "dir": "Both", "depth": 2}), "what links to the row, two hops");
    let edges = g["Ok"].as_array().cloned().unwrap_or_default();
    let has = |s: &str| edges.iter().any(|e| e.to_string().contains(s));
    run.nums.insert("graph".into(), json!({"edges": edges.len(), "has_grant": has(&format!("cap:{grant_id}")), "has_commit": has("at commit"), "has_reader": has("read by"), "has_row": has(&row)}));

    // ---------------------------------------------------------------- 7. phone offline
    run.ctl("phone", "Cut", json!(["*"]));
    for n in ["laptop", "server", "enterprise"] {
        run.ctl(n, "Cut", json!(["phone"]));
    }
    let mut offline = 0;
    let mut offline_refs = vec![];
    for r in [plan_id.clone(), huey_pinned.clone(), "cell:erp.orders@1".to_string()] {
        let (v, _) = run.call(7, "phone", "phone", "ref.resolve", "Resolve", json!({"reference": r}), "phone is cut off: from its local index");
        if v["Ok"]["Located"]["source"] == json!("local index") {
            offline += 1;
        }
        offline_refs.push(json!({"ref": r, "source": v["Ok"]["Located"]["source"], "as_of_ms": v["Ok"]["Located"]["as_of_ms"]}));
    }
    run.call(7, "enterprise", "phone", "ref.pin", "Fetch", json!({"pinned": inv_pinned}), "enterprise cannot reach phone");
    for n in NODES {
        run.ctl(n, "Heal", Value::Null);
    }
    let (healed, _) = run.call(7, "phone", "phone", "ref.resolve", "Resolve", json!({"reference": plan_id}), "healed: the mesh answers again");
    run.nums.insert("offline".into(), json!({"resolved": offline, "of": 3, "refs": offline_refs, "after_heal": healed["Ok"]["Located"]["source"]}));

    // ---------------------------------------------------------------- 8. "run.py" is refused; the pinned form works
    let (amb, _) = run.call(8, "enterprise", "enterprise", "ref.resolve", "Resolve", json!({"reference": "run.py"}), "a bare name");
    let bare_src = "cal 1\nperson:leif grants agent:reporter {\n  can proc.spawn:run\n  on node:enterprise\n  for 1d\n  only { spawn run.py at /srv/run.py on node:enterprise }\n  nonce 8\n}\n";
    let t1 = Instant::now();
    let cal_bare = cal::compile_text(bare_src, &refbook);
    run.local(8, "enterprise", "cal", "compile", json!({"source": bare_src}), json!({"refused": cal_bare.clone().err()}), cal_bare.is_ok(), t1.elapsed().as_secs_f64() * 1000.0, "CAL refuses the same bare name");
    let (ok, _) = run.call(8, "enterprise", "enterprise", "ref.resolve", "Resolve", json!({"reference": huey_pinned}), "the pinned form");
    let refused = amb["Ok"]["Ambiguous"].is_object() as u32;
    let accepted = ok["Ok"]["Located"].is_object() as u32;
    run.nums.insert("ambiguity".into(), json!({"refused": refused, "accepted": accepted, "candidates": amb["Ok"]["Ambiguous"]["candidates"], "cal": cal_bare.err()}));

    // ---------------------------------------------------------------- numbers and files
    run.nums.insert("resolve_ms".into(), json!({"n": run.resolve_ms.len(), "p50": pct(&run.resolve_ms, 50.0), "p95": pct(&run.resolve_ms, 95.0)}));
    run.nums.insert("ids".into(), crate::ids::identity());
    run.nums.insert("nodes_up_ms".into(), json!(up_ms));
    run.nums.insert("contracts".into(), json!(schemas));
    run.nums.insert("membership_grant".into(), json!(membership_src));
    run.nums.insert("cards".into(), json!(cards));
    run.nums.insert("steps".into(), json!(run.log.steps.len()));
    run.nums.insert("total_ms".into(), json!((t_all.elapsed().as_secs_f64() * 1000.0).round()));
    run.nums.insert("mode".into(), json!("sim: four processes on 127.0.0.1"));
    let _ = (tam, f1, v2);
    run.ctl.stop_all();

    std::fs::create_dir_all(out).unwrap();
    std::fs::write(out.join("run.jsonl"), run.log.jsonl()).unwrap();
    let pubs = json!({"root": key_hex(&root), "nodes": roster.nodes.iter().map(|(n, m)| (n.clone(), json!(m.key))).collect::<BTreeMap<_, _>>()});
    std::fs::write(out.join("roster.json"), serde_json::to_string_pretty(&pubs).unwrap()).unwrap();
    std::fs::write(out.join("summary.json"), serde_json::to_string_pretty(&run.nums).unwrap() + "\n").unwrap();
    print_summary(&run.nums);
    let _ = std::fs::remove_dir_all(&run.dir);
    Ok(())
}

fn print_summary(n: &BTreeMap<String, Value>) {
    println!("live-refs sim: {} steps in {} ms", n["steps"], n["total_ms"]);
    println!("  1 kinds resolved       {}", n["kinds_resolved"].as_str().unwrap());
    println!("    resolve              p50 {} ms, p95 {} ms over {} resolves", n["resolve_ms"]["p50"], n["resolve_ms"]["p95"], n["resolve_ms"]["n"]);
    println!("  2 move laptop->server  converged {} in {} ms, same id {}", n["move"]["converged"], n["move"]["ms"], n["move"]["same_id"]);
    println!("  3+4 tamper refusals    {}", n["tamper_refusals"].as_str().unwrap());
    println!("  4 grant                allowed {}, other op refused {}, tampered refused {}", n["grant"]["allowed"], n["grant"]["other_op_refused"], n["grant"]["tampered_refused"]);
    println!("  5 record               row on server, file on {}, read from enterprise, bytes ok {}", n["record"]["file_on"], n["record"]["bytes_ok"]);
    println!("  6 graph                {} edges; grant {}, commit {}, reader {}", n["graph"]["edges"], n["graph"]["has_grant"], n["graph"]["has_commit"], n["graph"]["has_reader"]);
    println!("  7 offline resolves     {} of 3 from phone's local index", n["offline"]["resolved"]);
    println!("  8 ambiguity            {} refused, {} accepted", n["ambiguity"]["refused"], n["ambiguity"]["accepted"]);
    println!("  ids byte-identical     {}", n["ids"]["summary"].as_str().unwrap_or(""));
}

pub fn verify(dir: &Path) -> Result<String, String> {
    let jsonl = std::fs::read_to_string(dir.join("run.jsonl")).map_err(|e| e.to_string())?;
    let pubs: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("roster.json")).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let root = format!("ed25519:{}", pubs["root"].as_str().unwrap_or(""));
    let n = live_proof::verify(&jsonl, &[root])?;
    // Each answer is also signed by the node that gave it.
    let mut roster = Roster { root: String::new(), nodes: BTreeMap::new() };
    for (k, v) in pubs["nodes"].as_object().unwrap() {
        roster.nodes.insert(k.clone(), Member { port: 0, key: v.as_str().unwrap().into() });
    }
    let mut answers = 0;
    for line in jsonl.lines() {
        let s: Step = serde_json::from_str(line).unwrap();
        let r = &s.response;
        if r["sig"].as_str().is_some_and(|x| !x.is_empty()) {
            let body = r["body"].clone();
            let refused = body.get("refused").and_then(|x| x.as_str()).map(String::from);
            let rep = sim_mesh::Reply { ok: refused.is_none(), body: if refused.is_some() { Value::Null } else { body }, refused, node: r["node"].as_str().unwrap().into(), sig: r["sig"].as_str().unwrap().into() };
            if !rep.verify(&roster) {
                return Err(format!("step {}: the answer is not signed by node:{}", s.n, rep.node));
            }
            answers += 1;
        }
    }
    let _ = Ref::parse("node:x");
    Ok(format!("{n} steps signed and chained; {answers} answers signed by the node that gave them"))
}
