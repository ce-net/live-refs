//! ref.resolve@1 on a real node. Answers from what this node can check itself: a repo path at a commit from its
//! checkouts, `node:` from its own identity, `cell:` from the cell.toml the door would start, and everything else
//! from the announcements in its local index (marked "local index" with the time of the newest one).
use ce_ref_id::Ref;
use ce_wire::Server;
use refs_wire::ref_resolve::*;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

fn home() -> PathBuf { PathBuf::from(std::env::var_os("HOME").unwrap_or_default()) }
fn index_file() -> PathBuf { let d = home().join(".local/state/live-refs/ref-resolve"); std::fs::create_dir_all(&d).ok(); d.join("index.json") }
fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 }
fn node() -> String { std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string() }
type Index = BTreeMap<String, BTreeMap<String, (Option<String>, u64, u64, String, String)>>;
fn load() -> Index { std::fs::read_to_string(index_file()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default() }

fn git(dir: &std::path::Path, args: &[&str]) -> Option<Vec<u8>> {
    let o = std::process::Command::new("git").arg("-C").arg(dir).args(args).output().ok()?;
    o.status.success().then_some(o.stdout)
}

fn me_key() -> String {
    ce_gate::node_identity().map(|i| i.node_id().iter().map(|b| format!("{b:02x}")).collect()).unwrap_or_default()
}

fn here(id: String, kind: &str, sha: Option<String>, size: u64, detail: String) -> Resolution {
    let h = Holder { node: node(), node_key: me_key(), sha256: sha.clone(), size, since_ms: now_ms(), live: true };
    Resolution::Located(Located { id, kind: kind.into(), holders: vec![h], pin: sha.map(|s| format!("sha256:{s}")), source: "mesh".into(), as_of_ms: now_ms(), detail })
}

fn resolve(written: &str) -> Resolution {
    let unknown = |reason: String| Resolution::Unknown { written: written.into(), reason };
    let r = match Ref::parse(written) { Ok(r) => r, Err(e) => return unknown(e.0) };
    match &r {
        Ref::Bare(name) => {
            // Every checkout on this node with a file of that name at its top: each is a different file.
            let mut c = vec![];
            let mut n = 0;
            for e in std::fs::read_dir(home().join("dev")).into_iter().flatten().flatten() {
                let p = e.path().join(name);
                if p.is_file() && e.path().join(".git").exists() {
                    n += 1;
                    if c.len() < 5 {
                        let repo = e.file_name().to_string_lossy().to_string();
                        let commit = git(&e.path(), &["rev-parse", "--short=7", "HEAD"]).map(|b| String::from_utf8_lossy(&b).trim().to_string()).unwrap_or_default();
                        if let Some(b) = git(&e.path(), &["show", &format!("HEAD:{name}")]) {
                            c.push(format!("repo:{repo}/{name}@{commit} sha256:{}", ce_ref_id::sha256_hex(&b)));
                        }
                    }
                }
            }
            let reason = format!("'{name}' is a bare path: {n} checkouts on node:{} have one, each a different file. Write one of the pinned forms (first {} shown).", node(), c.len());
            if n > 1 { Resolution::Ambiguous { written: written.into(), reason, candidates: c } } else { unknown(reason) }
        }
        Ref::RepoAt { repo, path, commit, sha256 } => {
            let dir = home().join("dev").join(repo);
            let Some(b) = git(&dir, &["show", &format!("{commit}:{path}")]) else { return unknown(format!("node:{} has no {repo}/{path} at {commit}", node())) };
            let sha = ce_ref_id::sha256_hex(&b);
            if sha256.as_ref().is_some_and(|w| *w != sha) {
                return unknown(format!("{repo}/{path}@{commit} is sha256:{sha} here, not the pinned sha256:{}", sha256.clone().unwrap()));
            }
            let origin = git(&dir, &["remote", "get-url", "origin"]).map(|b| String::from_utf8_lossy(&b).trim().to_string()).unwrap_or_default();
            let id = ce_ref_id::file_ref(&origin, path).map(|f| f.id()).unwrap_or(r.id());
            here(id, "file", Some(sha), b.len() as u64, format!("{} | checkout ~/dev/{repo} at {commit}", r.id()))
        }
        Ref::Node { name, .. } if *name == node() || *name == me_key() => here(format!("node:{}", node()), "node", None, 0, format!("node id {}", me_key())),
        Ref::Cell { api, major, op } => match ce_wire::find_manifest(api) {
            Some(m) => here(format!("cell:{api}@{major}"), "cell", None, 0, format!("{}cell.toml {}", op.as_ref().map(|o| format!("op {o} | ")).unwrap_or_default(), m.display())),
            None => from_index(written, &r),
        },
        _ => from_index(written, &r),
    }
}

fn from_index(written: &str, r: &Ref) -> Resolution {
    let ix = load();
    let Some(hs) = ix.get(&r.id()).filter(|m| !m.is_empty()) else {
        return Resolution::Unknown { written: written.into(), reason: format!("nothing in node:{}'s index holds {}", node(), r.id()) };
    };
    let holders: Vec<Holder> = hs.iter().map(|(n, (sha, size, at, _, _))| Holder { node: n.clone(), node_key: String::new(), sha256: sha.clone(), size: *size, since_ms: *at, live: *n == node() }).collect();
    let (sha, _, at, kind, detail) = hs.values().next().unwrap().clone();
    let live = holders.iter().any(|h| h.live);
    Resolution::Located(Located { id: r.id(), kind, pin: sha.map(|s| format!("sha256:{s}")), source: if live { "mesh".into() } else { "local index".into() }, as_of_ms: at, detail, holders })
}

fn publish(a: Announce) -> Result<u64, RefError> {
    let mut ix = load();
    let e = ix.entry(a.id.clone()).or_default();
    if a.gone { e.remove(&a.node); } else { e.insert(a.node.clone(), (a.sha256, a.size, a.at_ms.max(1), a.kind, a.detail)); }
    std::fs::write(index_file(), serde_json::to_vec(&ix).unwrap()).map_err(|e| RefError::Unavailable(e.to_string()))?;
    Ok(ix.values().map(|m| m.len() as u64).sum())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let me = ce_gate::node_identity().map_err(|e| e.to_string())?;
    let started = Instant::now();
    let gate = ce_gate::Gate::<RefResolve>::new(me.node_id(), ce_gate::mesh_roots()).into_fn();
    Server::<RefResolve>::new(gate)
        .on::<HealthOp, _, _>(move |_: (), _| async move { Ok(Health { ok: true, version: env!("CARGO_PKG_VERSION").into(), uptime_s: started.elapsed().as_secs() }) })
        .on::<Resolve, _, _>(|r: ResolveReq, _| async move { Ok(Ok(tokio::task::spawn_blocking(move || resolve(&r.reference)).await.unwrap())) })
        .on::<Publish, _, _>(|a: Announce, _| async move { Ok(tokio::task::spawn_blocking(move || publish(a)).await.unwrap()) })
        .serve_door()
        .await
        .map_err(|e| e.to_string())
}
