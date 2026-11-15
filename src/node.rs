//! One node of the mesh: its door (sim-mesh) and the cells it serves: ref.resolve@1, ref.pin@1, ref.graph@1,
//! refs.catalog@1, and on the node that runs it, erp.orders@1 (an ordinary HTTP program, wrapped).
//!
//! Every call is gated before a cell sees it: the caller's membership grant (a cap v3 chain written in CAL and
//! signed by the mesh root) must allow the op's right at this node. erp.orders ops are gated by the grant the
//! caller presents instead, and its executor checks the hash of the program file the grant pins.

use crate::cal;
use ce_ref_id::{typed::*, Ref};
use refs_api::{erp_orders as erp, ref_graph as rg, ref_pin as rp, ref_resolve as rr, refs_catalog as rc, Api, Op};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sim_mesh::{now_ms, Frame, Mesh, Reply, CTL};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default, Serialize, Deserialize)]
pub struct State {
    /// id -> node -> the newest announcement from that node.
    pub index: BTreeMap<String, BTreeMap<String, rr::Announce>>,
    /// Files held here: id -> (written form, commit). The bytes are on disk under files/.
    pub held: BTreeMap<String, (String, String)>,
    pub edges: Vec<rg::Edge>,
    pub rows: BTreeMap<String, rc::Asset>,
}

pub struct Node {
    pub mesh: Arc<Mesh>,
    pub dir: PathBuf,
    pub book: Value,
    pub state: Mutex<State>,
    pub gate_cache: Mutex<BTreeSet<(String, String)>>,
    pub started: Instant,
    pub erp_port: Mutex<Option<u16>>,
}

fn t(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

impl Node {
    pub fn load(dir: &Path) -> Arc<Node> {
        let me: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("me.json")).unwrap()).unwrap();
        let roster = serde_json::from_str(&std::fs::read_to_string(dir.join("../roster.json")).unwrap()).unwrap();
        let book: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("../book.json")).unwrap()).unwrap();
        let name = me["name"].as_str().unwrap();
        let mesh = Mesh::new(name, sim_mesh::key_from_hex(me["seed"].as_str().unwrap()), roster);
        let state = std::fs::read_to_string(dir.join("state.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        std::fs::create_dir_all(dir.join("files")).unwrap();
        Arc::new(Node { mesh, dir: dir.into(), book, state: Mutex::new(state), gate_cache: Mutex::new(BTreeSet::new()), started: Instant::now(), erp_port: Mutex::new(None) })
    }

    fn save(&self, s: &State) {
        let tmp = self.dir.join("state.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(s).unwrap()).unwrap();
        std::fs::rename(tmp, self.dir.join("state.json")).unwrap();
    }

    fn name(&self) -> &str {
        &self.mesh.name
    }

    fn peers(&self) -> Vec<String> {
        self.mesh.roster.nodes.keys().filter(|n| *n != self.name()).cloned().collect()
    }

    fn file_path(&self, id: &str) -> PathBuf {
        self.dir.join("files").join(ce_ref_id::sha256_hex(id.as_bytes()))
    }

    // ------------------------------------------------------------------ the door's gate

    fn gate(&self, f: &Frame, right: &str) -> Result<(), String> {
        let key = (f.from.clone(), right.to_string());
        if self.gate_cache.lock().unwrap().contains(&key) {
            return Ok(());
        }
        let tok = self.book["membership"][&f.from].as_str().ok_or(format!("gate: {} holds no grant here", f.from))?;
        let v = cal::check_do(tok, &format!("node:{}", self.name()), &format!("node:{}", f.from), right, &self.book["refs"])?;
        if v.allowed {
            self.gate_cache.lock().unwrap().insert(key);
            Ok(())
        } else {
            Err(format!("gate: {}", v.reason))
        }
    }

    fn op<O: Op, F: FnOnce(O::Req) -> O::Resp>(&self, f: &Frame, h: F) -> Reply {
        if let Err(e) = self.gate(f, O::RIGHT) {
            return Reply::refused(e);
        }
        match serde_json::from_value::<O::Req>(f.body.clone()) {
            Ok(req) => Reply::ok(serde_json::to_value(h(req)).unwrap()),
            Err(e) => Reply::refused(format!("{}.{}: request does not match the contract: {e}", <O::Api as Api>::NAME, O::NAME)),
        }
    }

    fn health(&self) -> rr::Health {
        rr::Health { ok: true, version: env!("CARGO_PKG_VERSION").into(), uptime_s: self.started.elapsed().as_secs() }
    }

    pub fn handle(self: &Arc<Self>, f: &Frame) -> Reply {
        match (f.api.as_str(), f.op.as_str()) {
            (CTL, _) => self.ctl(f),
            ("ref.resolve", "HealthOp") => self.op::<rr::HealthOp, _>(f, |_| self.health()),
            ("ref.resolve", "Resolve") => self.op::<rr::Resolve, _>(f, |r| Ok(self.resolve(&r.reference))),
            ("ref.resolve", "Publish") => self.op::<rr::Publish, _>(f, |a| Ok(self.publish_local(a))),
            ("ref.pin", "HealthOp") => self.op::<rp::HealthOp, _>(f, |_| rp::Health { ok: true, version: env!("CARGO_PKG_VERSION").into(), uptime_s: 0 }),
            ("ref.pin", "Pin") => self.op::<rp::Pin, _>(f, |r| self.pin(&r.reference)),
            ("ref.pin", "Verify") => self.op::<rp::Verify, _>(f, |r| self.fetch(&r.pinned).map(|x| match x {
                rp::Fetched::Ok { sha256, .. } => rp::Verdict::Ok { sha256 },
                rp::Fetched::Refused { want, got } => rp::Verdict::Refused { want, got },
            })),
            ("ref.pin", "Fetch") => self.op::<rp::Fetch, _>(f, |r| self.fetch(&r.pinned)),
            ("ref.pin", "Put") => self.op::<rp::Put, _>(f, |r| self.put(&r.id, &r.id, "", &r.bytes)),
            ("ref.graph", "Links") => self.op::<rg::Links, _>(f, |r| self.links(&r)),
            ("ref.graph", "Add") => self.op::<rg::Add, _>(f, |e| Ok(self.add_edge_local(e))),
            ("refs.catalog", "Insert") => self.op::<rc::Insert, _>(f, |a| self.insert(a)),
            ("refs.catalog", "Get") => self.op::<rc::Get, _>(f, |id| {
                let s = self.state.lock().unwrap();
                s.rows.get(&id).cloned().ok_or(rc::CatalogError::NotFound(id))
            }),
            ("erp.orders", op) if self.erp_port.lock().unwrap().is_some() => self.erp(f, op),
            (api, op) => Reply::refused(format!("door: {} serves no {api}.{op}", self.name())),
        }
    }

    // ------------------------------------------------------------------ ref.resolve

    /// Writes an announcement into the local index (what every Publish does).
    fn publish_local(&self, a: rr::Announce) -> u64 {
        let mut s = self.state.lock().unwrap();
        let e = s.index.entry(a.id.clone()).or_default();
        if a.gone {
            e.remove(&a.node);
        } else {
            e.insert(a.node.clone(), a);
        }
        let n = s.index.values().map(|m| m.len() as u64).sum();
        self.save(&s);
        n
    }

    /// Announces to this node's index and every peer it can reach. Returns the peers reached.
    fn announce(&self, a: rr::Announce) -> Vec<String> {
        self.publish_local(a.clone());
        let mut reached = vec![];
        for p in self.peers() {
            if let Ok(r) = self.mesh.call(&p, "ref.resolve", "Publish", serde_json::to_value(&a).unwrap(), t(400)) {
                if r.ok {
                    reached.push(p);
                }
            }
        }
        reached
    }

    fn repo_origins(&self, repo: &str) -> Vec<String> {
        self.book["refs"]["repos"][repo].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
    }

    /// The id a file ref is stored under: its portable `ce-ref://repo/...` id.
    fn file_id(&self, r: &Ref) -> Result<String, rr::Resolution> {
        match r {
            Ref::RepoAt { repo, path, .. } => {
                let o = self.repo_origins(repo);
                match o.len() {
                    0 => Err(rr::Resolution::Unknown { written: r.to_string(), reason: format!("no repository named {repo} is known to node:{}", self.name()) }),
                    1 => Ok(ce_ref_id::file_ref(&o[0], path).unwrap().id()),
                    _ => Err(rr::Resolution::Ambiguous { written: r.to_string(), reason: format!("{repo} names {} repositories", o.len()), candidates: o }),
                }
            }
            other => Ok(other.id()),
        }
    }

    fn holder_live(&self, h: &rr::Announce) -> bool {
        if h.node == self.name() {
            return true;
        }
        match &h.sha256 {
            // A file holder is live when it still holds those bytes now.
            Some(sha) if h.kind.starts_with("file") || h.kind == "blob" => {
                let b = json!({"reference": h.id});
                matches!(self.mesh.call(&h.node, "ref.pin", "Pin", b, t(300)), Ok(r) if r.body["Ok"]["sha256"].as_str() == Some(sha))
            }
            _ => matches!(self.mesh.call(&h.node, "ref.resolve", "HealthOp", Value::Null, t(300)), Ok(r) if r.ok),
        }
    }

    pub fn resolve(&self, written: &str) -> rr::Resolution {
        let unknown = |why: String| rr::Resolution::Unknown { written: written.into(), reason: why };
        let r = match Ref::parse(written) {
            Ok(r) => r,
            Err(e) => return unknown(e.0),
        };
        if let Ref::Bare(name) = &r {
            // A bare name is never resolved: every file of that name anywhere is a candidate, each in pinned form.
            let s = self.state.lock().unwrap();
            let mut c = BTreeSet::new();
            for (id, hs) in &s.index {
                if id.starts_with("ce-ref://") && id.rsplit('/').next() == Some(name.as_str()) {
                    for h in hs.values() {
                        let w = if h.detail.starts_with("repo:") { h.detail.split(" | ").next().unwrap().to_string() } else { id.clone() };
                        c.insert(format!("{w} sha256:{}", h.sha256.clone().unwrap_or_default()));
                    }
                }
            }
            let reason = format!("'{name}' is a bare path: it names a different file on every machine ({} known here). Write one of the pinned forms.", c.len());
            return if c.len() > 1 { rr::Resolution::Ambiguous { written: written.into(), reason, candidates: c.into_iter().collect() } } else { unknown(reason) };
        }
        let id = match &r {
            Ref::File { .. } | Ref::RepoAt { .. } => match self.file_id(&r) {
                Ok(i) => i,
                Err(res) => return res,
            },
            Ref::Cell { api, major, op } => {
                if let Some(o) = op {
                    if refs_api::right_of(api, o).is_none() {
                        return unknown(format!("cell:{api}@{major} has no op {o} in its contract"));
                    }
                }
                format!("cell:{api}@{major}")
            }
            Ref::Node { name, .. } => {
                let Some(m) = self.mesh.roster.nodes.get(name) else { return unknown(format!("node:{name} is not in this mesh")) };
                let a = rr::Announce { id: r.id(), kind: "node".into(), node: name.clone(), sha256: None, size: 0, at_ms: now_ms(), gone: false, detail: format!("ed25519:{}", m.key) };
                let live = self.holder_live(&a);
                let detail = format!("node key ed25519:{} at 127.0.0.1:{}", m.key, m.port);
                return rr::Resolution::Located(rr::Located {
                    id: r.id(), kind: "node".into(), pin: Some(format!("ed25519:{}", m.key)), source: if live { "mesh".into() } else { "roster".into() }, as_of_ms: now_ms(), detail,
                    holders: vec![rr::Holder { node: name.clone(), node_key: m.key.clone(), sha256: None, size: 0, since_ms: 0, live }],
                });
            }
            Ref::Named(_) | Ref::Bare(_) => r.id(),
            other => other.id(),
        };
        let entries: Vec<rr::Announce> = self.state.lock().unwrap().index.get(&id).map(|m| m.values().cloned().collect()).unwrap_or_default();
        if entries.is_empty() {
            return unknown(format!("nothing in node:{}'s index holds {id}", self.name()));
        }
        // A pinned file ref only matches holders of exactly those bytes; a commit must match the observed one.
        let want = match &r {
            Ref::File { sha256, .. } | Ref::RepoAt { sha256, .. } => sha256.clone(),
            _ => None,
        };
        let mut entries: Vec<rr::Announce> = entries.into_iter().filter(|h| want.is_none() || h.sha256 == want).collect();
        if let Ref::RepoAt { commit, .. } = &r {
            entries.retain(|h| h.detail.split(" | ").any(|d| d.starts_with("commit ") && d[7..].starts_with(commit.as_str())));
        }
        if entries.is_empty() {
            return unknown(format!("no holder of {id} has {}", want.map(|w| format!("sha256:{w}")).unwrap_or("that commit".into())));
        }
        let shas: BTreeSet<_> = entries.iter().filter_map(|h| h.sha256.clone()).collect();
        if want.is_none() && shas.len() > 1 {
            return rr::Resolution::Ambiguous { written: written.into(), reason: format!("{id} has {} different contents on the mesh; pin one", shas.len()), candidates: shas.iter().map(|s| format!("{id} sha256:{s}")).collect() };
        }
        let mut holders = vec![];
        let mut any_live = false;
        for h in &entries {
            let live = self.holder_live(h);
            any_live |= live;
            let key = self.mesh.roster.nodes.get(&h.node).map(|m| m.key.clone()).unwrap_or_default();
            holders.push(rr::Holder { node: h.node.clone(), node_key: key, sha256: h.sha256.clone(), size: h.size, since_ms: h.at_ms, live });
        }
        let pin = match &r {
            Ref::Principal { .. } | Ref::Cap { .. } | Ref::Cell { .. } => entries[0].detail.split(" | ").find(|d| d.starts_with("ed25519:") || d.starts_with("p256:")).map(String::from),
            _ => shas.iter().next().map(|s| format!("sha256:{s}")),
        };
        let mut detail = entries[0].detail.clone();
        if let Ref::Cell { api, op: Some(o), .. } = &r {
            detail = format!("op {o} needs {} | {detail}", refs_api::right_of(api, o).unwrap());
        }
        rr::Resolution::Located(rr::Located {
            id,
            kind: entries[0].kind.clone(),
            holders,
            pin,
            source: if any_live { "mesh".into() } else { "local index".into() },
            as_of_ms: entries.iter().map(|h| h.at_ms).max().unwrap_or(0),
            detail,
        })
    }

    // ------------------------------------------------------------------ ref.pin

    fn put(&self, id: &str, written: &str, commit: &str, bytes: &[u8]) -> Result<rp::PinnedRef, rp::PinError> {
        std::fs::write(self.file_path(id), bytes).map_err(|e| rp::PinError::Invalid(e.to_string()))?;
        let mut s = self.state.lock().unwrap();
        s.held.insert(id.into(), (written.into(), commit.into()));
        self.save(&s);
        let sha = ce_ref_id::sha256_hex(bytes);
        Ok(rp::PinnedRef { reference: format!("{id} sha256:{sha}"), sha256: sha, size: bytes.len() as u64, node: self.name().into() })
    }

    fn read_held(&self, r: &Ref) -> Result<(String, Vec<u8>), rp::PinError> {
        let id = self.file_id(r).map_err(|_| rp::PinError::Invalid(format!("{r}: not a file this node can name")))?;
        if !self.state.lock().unwrap().held.contains_key(&id) {
            return Err(rp::PinError::NotHere(format!("node:{} does not hold {id}", self.name())));
        }
        let b = std::fs::read(self.file_path(&id)).map_err(|e| rp::PinError::NotHere(e.to_string()))?;
        Ok((id, b))
    }

    fn pin(&self, written: &str) -> Result<rp::PinnedRef, rp::PinError> {
        let r = Ref::parse(written).map_err(|e| rp::PinError::Invalid(e.0))?;
        let (id, b) = self.read_held(&r)?;
        let sha = ce_ref_id::sha256_hex(&b);
        Ok(rp::PinnedRef { reference: format!("{id} sha256:{sha}"), sha256: sha, size: b.len() as u64, node: self.name().into() })
    }

    /// Only the pinned bytes leave this node: a different content hash is refused, with both hashes.
    fn fetch(&self, pinned: &str) -> Result<rp::Fetched, rp::PinError> {
        let r = Typed::<FileK>::parse(pinned).and_then(|t| t.pinned()).map_err(|e| rp::PinError::Invalid(format!("{e}: Fetch takes a pinned file ref")))?;
        let want = match r.get() {
            Ref::Blob { sha256 } => sha256.clone(),
            other => other.pin().unwrap().trim_start_matches("sha256:").to_string(),
        };
        let (_, b) = self.read_held(r.get())?;
        let got = ce_ref_id::sha256_hex(&b);
        Ok(if got == want { rp::Fetched::Ok { sha256: got, bytes: b } } else { rp::Fetched::Refused { want: format!("sha256:{want}"), got: format!("sha256:{got}") } })
    }

    // ------------------------------------------------------------------ ref.graph

    fn add_edge_local(&self, e: rg::Edge) -> u64 {
        let mut s = self.state.lock().unwrap();
        if !s.edges.contains(&e) {
            s.edges.push(e);
        }
        self.save(&s);
        s.edges.len() as u64
    }

    fn links(&self, q: &rg::LinksReq) -> Result<Vec<rg::Edge>, rg::GraphError> {
        let s = self.state.lock().unwrap();
        // Recorded edges, plus where each thing lives now from the index.
        let mut all = s.edges.clone();
        for (id, hs) in &s.index {
            for h in hs.values() {
                let why = if h.kind.starts_with("cell") { "runs on" } else { "lives on" };
                all.push(rg::Edge { from: id.clone(), to: format!("node:{}", h.node), why: why.into(), evidence: format!("ref.resolve announcement at {} ms", h.at_ms) });
            }
        }
        let start = Ref::parse(&q.reference).map(|r| r.id()).unwrap_or(q.reference.clone());
        let norm = |x: &str| Ref::parse(x).map(|r| r.id()).unwrap_or(x.to_string());
        let (mut seen, mut frontier, mut out) = (BTreeSet::from([start.clone()]), vec![start], Vec::new());
        for _ in 0..q.depth.max(1) {
            let mut next = vec![];
            for e in &all {
                let (f, t) = (norm(&e.from), norm(&e.to));
                let hit_out = !matches!(q.dir, rg::Dir::In) && frontier.contains(&f);
                let hit_in = !matches!(q.dir, rg::Dir::Out) && frontier.contains(&t);
                if (hit_out || hit_in) && !out.contains(e) {
                    out.push(e.clone());
                    for n in [f, t] {
                        if seen.insert(n.clone()) && !n.starts_with("node:") {
                            next.push(n);
                        }
                    }
                }
            }
            frontier = next;
        }
        Ok(out)
    }

    fn add_edges(&self, es: Vec<rg::Edge>) {
        for e in es {
            self.add_edge_local(e.clone());
            for p in self.peers() {
                let _ = self.mesh.call(&p, "ref.graph", "Add", serde_json::to_value(&e).unwrap(), t(400));
            }
        }
    }

    // ------------------------------------------------------------------ refs.catalog

    fn insert(&self, a: rc::Asset) -> Result<u64, rc::CatalogError> {
        let bad = |e: ce_ref_id::Error| rc::CatalogError::Invalid(e.0);
        Typed::<FileK>::parse(&a.file).map_err(bad)?;
        if let Some(p) = &a.pinned {
            Typed::<FileK>::parse(p).and_then(|x| x.pinned()).map_err(bad)?;
        }
        Typed::<PersonK>::parse(&a.owner).map_err(bad)?;
        let row = format!("row:refs.catalog/{}", a.id);
        let mut es = vec![
            rg::Edge { from: row.clone(), to: a.file.clone(), why: "field file".into(), evidence: format!("refs.catalog row {} on node:{}", a.id, self.name()) },
            rg::Edge { from: row.clone(), to: a.owner.clone(), why: "field owner".into(), evidence: format!("refs.catalog row {}", a.id) },
        ];
        if let Some(p) = &a.pinned {
            es.push(rg::Edge { from: row.clone(), to: p.clone(), why: "field pinned".into(), evidence: format!("refs.catalog row {}", a.id) });
        }
        {
            let mut s = self.state.lock().unwrap();
            s.rows.insert(a.id.clone(), a);
            self.save(&s);
        }
        self.add_edges(es);
        Ok(self.state.lock().unwrap().rows.len() as u64)
    }

    // ------------------------------------------------------------------ erp.orders: the wrapped system

    fn erp_http(&self, path: &str) -> Result<(u16, String), String> {
        use std::io::{Read, Write};
        let port = self.erp_port.lock().unwrap().ok_or("erp-legacy is not running")?;
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        write!(s, "GET {path} HTTP/1.0\r\n\r\n").map_err(|e| e.to_string())?;
        let mut out = String::new();
        s.read_to_string(&mut out).map_err(|e| e.to_string())?;
        let code = out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
        Ok((code, out.split("\r\n\r\n").nth(1).unwrap_or("").to_string()))
    }

    /// The executor: the presented grant must allow this op at this node, and the report file it pins is fetched
    /// from wherever it lives now and hashed against the pin before the order system is asked.
    fn erp(self: &Arc<Self>, f: &Frame, op: &str) -> Reply {
        let req: erp::OrderReq = match serde_json::from_value(f.body.clone()) {
            Ok(r) => r,
            Err(e) => return Reply::refused(format!("erp.orders.{op}: request does not match the contract: {e}")),
        };
        if op == "HealthOp" {
            return Reply::ok(json!({"ok": true, "version": "1", "uptime_s": 0}));
        }
        let refs = &self.book["refs"];
        let node = format!("node:{}", self.name());
        let as_ = "agent:reporter";
        let refuse = |why: String| Reply::ok(serde_json::to_value(Err::<erp::Order, _>(erp::ErpError::Refused(why))).unwrap());
        if op != "GetOrder" {
            let right = refs_api::right_of("erp.orders", op).unwrap_or(format!("erp.orders:{op}"));
            return match cal::check_do(&req.grant, &node, as_, &right, refs) {
                Ok(v) if v.allowed => refuse("not reached".into()),
                Ok(v) => refuse(format!("CAL: {}", v.text.trim())),
                Err(e) => refuse(e),
            };
        }
        // Step 0 of the bound program runs the pinned report: find it now, fetch it, let CAL hash it.
        let report = match Ref::parse(&req.report) {
            Ok(r) => r,
            Err(e) => return refuse(e.0),
        };
        let at = match self.resolve(&report.id()) {
            // Any holder that answers: the hash is checked below, by CAL, not here.
            rr::Resolution::Located(l) => match l.holders.iter().find(|h| h.live).or(l.holders.first()) {
                Some(h) => h.node.clone(),
                None => return refuse(format!("{} has no holder", report.id())),
            },
            other => return refuse(format!("{other:?}")),
        };
        let current = match self.mesh.call(&at, "ref.pin", "Pin", json!({"reference": report.id()}), t(1000)) {
            Ok(r) if r.ok => r.body["Ok"]["reference"].as_str().unwrap_or("").to_string(),
            other => return refuse(format!("ref.pin.Pin at node:{at}: {other:?}")),
        };
        let bytes = match self.mesh.call(&at, "ref.pin", "Fetch", json!({"pinned": current}), t(1000)) {
            Ok(r) => match serde_json::from_value::<Result<rp::Fetched, rp::PinError>>(r.body) {
                Ok(Ok(rp::Fetched::Ok { bytes, .. })) => bytes,
                other => return refuse(format!("ref.pin.Fetch at node:{at}: {other:?}")),
            },
            Err(e) => return refuse(e),
        };
        match cal::check_step(&req.grant, &node, as_, &req.program, 0, &bytes, refs) {
            Ok(v) if v.allowed => {}
            Ok(v) => return refuse(format!("CAL: {}", v.text.trim())),
            Err(e) => return refuse(e),
        }
        match cal::check_step(&req.grant, &node, as_, &req.program, 1, &[], refs) {
            Ok(v) if v.allowed || v.reason.contains("names no file content") => {}
            Ok(v) => return refuse(format!("CAL: {}", v.text.trim())),
            Err(e) => return refuse(e),
        }
        match self.erp_http(&format!("/orders/{}", req.id)) {
            Ok((200, body)) => {
                let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                let o = erp::Order {
                    id: v["id"].as_str().unwrap_or("").into(),
                    customer: v["customer"].as_str().unwrap_or("").into(),
                    total_cents: v["total_cents"].as_u64().unwrap_or(0),
                    status: v["status"].as_str().unwrap_or("").into(),
                    served_by: format!("erp-legacy over HTTP on node:{} (report fetched from node:{at})", self.name()),
                };
                Reply::ok(serde_json::to_value(Ok::<_, erp::ErpError>(o)).unwrap())
            }
            Ok((code, body)) => Reply::ok(serde_json::to_value(Err::<erp::Order, _>(erp::ErpError::NotFound(format!("{code} {body}")))).unwrap()),
            Err(e) => Reply::ok(serde_json::to_value(Err::<erp::Order, _>(erp::ErpError::Unavailable(e))).unwrap()),
        }
    }

    pub fn start_erp(&self) -> Result<String, String> {
        let exe = std::env::current_exe().unwrap().with_file_name("erp-legacy");
        let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = l.local_addr().unwrap().port();
        drop(l);
        std::process::Command::new(&exe).args(["--port", &port.to_string()]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).spawn().map_err(|e| format!("{}: {e}", exe.display()))?;
        for _ in 0..100 {
            *self.erp_port.lock().unwrap() = Some(port);
            if matches!(self.erp_http("/health"), Ok((200, _))) {
                let bin = std::fs::read(&exe).map_err(|e| e.to_string())?;
                return Ok(ce_ref_id::sha256_hex(&bin));
            }
            std::thread::sleep(t(20));
        }
        *self.erp_port.lock().unwrap() = None;
        Err("erp-legacy did not answer /health".into())
    }

    // ------------------------------------------------------------------ control (root-signed only)

    fn ctl(self: &Arc<Self>, f: &Frame) -> Reply {
        let b = &f.body;
        let s = |k: &str| b[k].as_str().unwrap_or("").to_string();
        match f.op.as_str() {
            "Ping" => Reply::ok(json!(self.name())),
            "Put" => {
                let bytes: Vec<u8> = serde_json::from_value(b["bytes"].clone()).unwrap_or_default();
                let id = s("id");
                match self.put(&id, &s("written"), &s("commit"), &bytes) {
                    Ok(p) => {
                        let mut detail = s("written");
                        if !s("commit").is_empty() {
                            detail += &format!(" | commit {}", s("commit"));
                        }
                        let a = rr::Announce { id, kind: s("kind"), node: self.name().into(), sha256: Some(p.sha256.clone()), size: p.size, at_ms: now_ms(), gone: false, detail };
                        let reached = self.announce(a);
                        Reply::ok(json!({"pinned": p, "announced_to": reached}))
                    }
                    Err(e) => Reply::refused(format!("{e:?}")),
                }
            }
            "Pull" => {
                // Take a file from another node: fetch exactly the pinned bytes, hold them, announce.
                let (id, from) = (s("id"), s("from"));
                let t0 = Instant::now();
                let pinned = match self.mesh.call(&from, "ref.pin", "Pin", json!({"reference": id}), t(1000)) {
                    Ok(r) if r.ok && r.body.get("Ok").is_some() => r.body["Ok"]["reference"].as_str().unwrap().to_string(),
                    other => return Reply::refused(format!("Pin at {from}: {other:?}")),
                };
                let fetched = match self.mesh.call(&from, "ref.pin", "Fetch", json!({"pinned": pinned}), t(1000)) {
                    Ok(r) => r,
                    Err(e) => return Reply::refused(e),
                };
                let ms = t0.elapsed().as_secs_f64() * 1000.0;
                let Some(bytes) = fetched.body["Ok"]["Ok"]["bytes"].as_array().map(|a| a.iter().map(|x| x.as_u64().unwrap() as u8).collect::<Vec<u8>>()) else {
                    return Reply::refused(format!("Fetch at {from}: {}", fetched.body));
                };
                let (written, commit) = serde_json::from_value::<(String, String)>(b["meta"].clone()).unwrap_or_default();
                let p = self.put(&id, &written, &commit, &bytes).unwrap();
                let mut detail = written;
                if !commit.is_empty() {
                    detail += &format!(" | commit {commit}");
                }
                let a = rr::Announce { id, kind: s("kind"), node: self.name().into(), sha256: Some(p.sha256.clone()), size: p.size, at_ms: now_ms(), gone: false, detail };
                let reached = self.announce(a);
                Reply::ok(json!({"pinned": p, "fetch": {"request": {"pinned": pinned}, "reply_node": fetched.node, "reply_sig": fetched.sig, "ms": ms}, "announced_to": reached}))
            }
            "Drop" => {
                let id = s("id");
                let _ = std::fs::remove_file(self.file_path(&id));
                let mut a = { self.state.lock().unwrap().index.get(&id).and_then(|m| m.get(self.name()).cloned()) }.unwrap_or(rr::Announce {
                    id: id.clone(), kind: s("kind"), node: self.name().into(), sha256: None, size: 0, at_ms: 0, gone: true, detail: String::new() });
                {
                    let mut st = self.state.lock().unwrap();
                    st.held.remove(&id);
                    self.save(&st);
                }
                a.gone = true;
                a.at_ms = now_ms();
                Reply::ok(json!({"announced_to": self.announce(a)}))
            }
            "Tamper" => {
                // Someone edits the file on this device behind the mesh's back: one byte changes.
                let p = self.file_path(&s("id"));
                match std::fs::read(&p) {
                    Ok(mut bytes) if !bytes.is_empty() => {
                        bytes[0] ^= 0x20;
                        std::fs::write(&p, &bytes).unwrap();
                        Reply::ok(json!({"sha256": ce_ref_id::sha256_hex(&bytes)}))
                    }
                    _ => Reply::refused("not held here"),
                }
            }
            "Announce" => match serde_json::from_value::<rr::Announce>(b.clone()) {
                Ok(mut a) => {
                    a.node = self.name().into();
                    a.at_ms = now_ms();
                    Reply::ok(json!({"announced_to": self.announce(a)}))
                }
                Err(e) => Reply::refused(e.to_string()),
            },
            "AddEdges" => {
                let es: Vec<rg::Edge> = serde_json::from_value(b.clone()).unwrap_or_default();
                self.add_edges(es);
                Reply::ok(json!(self.state.lock().unwrap().edges.len()))
            }
            "Cut" => {
                let peers: Vec<String> = serde_json::from_value(b.clone()).unwrap_or_default();
                self.mesh.cut.lock().unwrap().extend(peers);
                Reply::ok(json!(true))
            }
            "Heal" => {
                self.mesh.cut.lock().unwrap().clear();
                Reply::ok(json!(true))
            }
            "StartErp" => match self.start_erp() {
                Ok(sha) => Reply::ok(json!({"binary_sha256": sha})),
                Err(e) => Reply::refused(e),
            },
            "Call" => {
                // This node makes a call itself; the answer comes back with the answering node's signature.
                let (to, api, op) = (s("to"), s("api"), s("op"));
                let t0 = Instant::now();
                let r = self.mesh.call(&to, &api, &op, b["body"].clone(), t(5000));
                let ms = t0.elapsed().as_secs_f64() * 1000.0;
                match r {
                    Ok(rep) => Reply::ok(json!({"reply": rep, "ms": ms})),
                    Err(e) => Reply::ok(json!({"error": e, "ms": ms})),
                }
            }
            "Index" => {
                let st = self.state.lock().unwrap();
                Reply::ok(json!({"ids": st.index.len(), "held": st.held.keys().collect::<Vec<_>>(), "edges": st.edges.len(), "rows": st.rows.len()}))
            }
            other => Reply::refused(format!("sim.ctl has no op {other}")),
        }
    }
}

pub fn run(dir: &Path) -> ! {
    let n = Node::load(dir);
    let n2 = n.clone();
    n.mesh.serve(move |f| n2.handle(f))
}
