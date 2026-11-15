//! ref.pin@1 on a real node: pins a file to its content hash and hands out only the pinned bytes. A repo path at a
//! commit is read from this node's own checkout (`git show <commit>:<path>` in ~/dev/<repo>); other files are held in
//! the cell's store (Put).
use ce_ref_id::{typed::*, Ref};
use ce_wire::Server;
use refs_wire::ref_pin::*;
use std::path::PathBuf;
use std::time::Instant;

fn home() -> PathBuf { PathBuf::from(std::env::var_os("HOME").unwrap_or_default()) }
fn store() -> PathBuf { let d = home().join(".local/state/live-refs/ref-pin"); std::fs::create_dir_all(&d).ok(); d }
fn slot(id: &str) -> PathBuf { store().join(ce_ref_id::sha256_hex(id.as_bytes())) }
fn node() -> String { std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string() }

/// The bytes a ref names on this node, and the id they are known by.
pub fn read(r: &Ref) -> Result<(String, Vec<u8>), PinError> {
    match r {
        Ref::RepoAt { repo, path, commit, .. } => {
            let dir = home().join("dev").join(repo);
            let origin = std::process::Command::new("git").arg("-C").arg(&dir).args(["remote", "get-url", "origin"]).output().map_err(|e| PinError::NotHere(e.to_string()))?;
            let origin = String::from_utf8_lossy(&origin.stdout).trim().to_string();
            let o = std::process::Command::new("git").arg("-C").arg(&dir).arg("show").arg(format!("{commit}:{path}")).output().map_err(|e| PinError::NotHere(e.to_string()))?;
            if !o.status.success() {
                return Err(PinError::NotHere(format!("node:{} has no {repo}/{path} at {commit}: {}", node(), String::from_utf8_lossy(&o.stderr).trim())));
            }
            let id = ce_ref_id::file_ref(&origin, path).map(|f| f.id()).unwrap_or(r.id());
            Ok((id, o.stdout))
        }
        other => {
            let id = other.id();
            std::fs::read(slot(&id)).map(|b| (id.clone(), b)).map_err(|_| PinError::NotHere(format!("node:{} does not hold {id}", node())))
        }
    }
}

fn pin(reference: &str) -> Result<PinnedRef, PinError> {
    let r = Ref::parse(reference).map_err(|e| PinError::Invalid(e.0))?;
    let (id, b) = read(&r)?;
    let sha = ce_ref_id::sha256_hex(&b);
    let written = if let Ref::RepoAt { .. } = r { format!("{} sha256:{sha}", r.id()) } else { format!("{id} sha256:{sha}") };
    Ok(PinnedRef { reference: written, sha256: sha, size: b.len() as u64, node: node() })
}

fn fetch(pinned: &str) -> Result<Fetched, PinError> {
    let p = Typed::<FileK>::parse(pinned).and_then(|t| t.pinned()).map_err(|e| PinError::Invalid(format!("{e}: Fetch takes a pinned file ref")))?;
    let want = match p.get() { Ref::Blob { sha256 } => sha256.clone(), o => o.pin().unwrap().trim_start_matches("sha256:").to_string() };
    let (_, b) = read(p.get())?;
    let got = ce_ref_id::sha256_hex(&b);
    Ok(if got == want { Fetched::Ok { sha256: got, bytes: b } } else { Fetched::Refused { want: format!("sha256:{want}"), got: format!("sha256:{got}") } })
}

fn put(r: PutReq) -> Result<PinnedRef, PinError> {
    let id = Ref::parse(&r.id).map_err(|e| PinError::Invalid(e.0))?.id();
    std::fs::write(slot(&id), &r.bytes).map_err(|e| PinError::Invalid(e.to_string()))?;
    let sha = ce_ref_id::sha256_hex(&r.bytes);
    Ok(PinnedRef { reference: format!("{id} sha256:{sha}"), sha256: sha, size: r.bytes.len() as u64, node: node() })
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let me = ce_gate::node_identity().map_err(|e| e.to_string())?;
    let started = Instant::now();
    let gate = ce_gate::Gate::<RefPin>::new(me.node_id(), ce_gate::mesh_roots()).into_fn();
    let b = |f: fn(&str) -> Result<PinnedRef, PinError>, s: String| async move { Ok(tokio::task::spawn_blocking(move || f(&s)).await.unwrap()) };
    Server::<RefPin>::new(gate)
        .on::<HealthOp, _, _>(move |_: (), _| async move { Ok(Health { ok: true, version: env!("CARGO_PKG_VERSION").into(), uptime_s: started.elapsed().as_secs() }) })
        .on::<Pin, _, _>(move |r: PinReq, _| b(pin, r.reference))
        .on::<Verify, _, _>(|r: VerifyReq, _| async move { Ok(tokio::task::spawn_blocking(move || fetch(&r.pinned).map(|f| match f {
            Fetched::Ok { sha256, .. } => Verdict::Ok { sha256 },
            Fetched::Refused { want, got } => Verdict::Refused { want, got },
        })).await.unwrap()) })
        .on::<Fetch, _, _>(|r: FetchReq, _| async move { Ok(tokio::task::spawn_blocking(move || fetch(&r.pinned)).await.unwrap()) })
        .on::<Put, _, _>(|r: PutReq, _| async move { Ok(tokio::task::spawn_blocking(move || put(r)).await.unwrap()) })
        .serve_door()
        .await
        .map_err(|e| e.to_string())
}
