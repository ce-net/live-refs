//! ref.graph@1 on a real node: edges from the live ref.extract cell (every reference between repos and cells on the
//! mesh, each with its why and the file:line that says it), plus edges added here.
use ce_ref_id::Ref;
use ce_wire::Server;
use refs_wire::ref_graph::*;
use std::time::Instant;

fn edges_file() -> std::path::PathBuf {
    let d = std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/state/live-refs/ref-graph");
    std::fs::create_dir_all(&d).ok();
    d.join("edges.json")
}

/// The id ref.extract knows a thing by.
fn extract_id(r: &str) -> String {
    match Ref::parse(r) {
        Ok(Ref::Cell { api, .. }) => format!("api:{api}"),
        Ok(Ref::RepoAt { repo, .. }) => format!("repo:{repo}"),
        Ok(x) => x.id(),
        Err(_) => r.to_string(),
    }
}

async fn links(q: LinksReq) -> Result<Vec<Edge>, GraphError> {
    let id = extract_id(&q.reference);
    let mut out: Vec<Edge> = std::fs::read_to_string(edges_file()).ok().and_then(|s| serde_json::from_str::<Vec<Edge>>(&s).ok()).unwrap_or_default()
        .into_iter().filter(|e| e.from == q.reference || e.to == q.reference).collect();
    let tok = ce_gate::self_proof::<ref_extract_api::RefExtract>(300).map_err(|e| GraphError::Unavailable(e.to_string()))?;
    let c = ce_wire::Client::<ref_extract_api::RefExtract>::connect_opts("127.0.0.1:7700", tok, true, std::time::Duration::from_secs(10)).await
        .map_err(|e| GraphError::Unavailable(format!("ref.extract: {e:?}")))?;
    let refs = c.call::<ref_extract_api::RefsOf>(&ref_extract_api::RefsReq { id: id.clone(), kinds: vec![], limit: 50 }).await
        .map_err(|e| GraphError::Unavailable(format!("ref.extract: {e:?}")))?
        .map_err(|e| GraphError::Invalid(format!("ref.extract: {e:?}")))?;
    let ev = |r: &ref_extract_api::Ref| r.evidence.first().map(|e| format!("{}:{}/{}:{} {}", e.machine, e.repo, e.path, e.line, e.text.chars().take(120).collect::<String>())).unwrap_or_default();
    for r in refs.out.iter().filter(|_| !matches!(q.dir, Dir::In)).chain(refs.back.iter().filter(|_| !matches!(q.dir, Dir::Out))) {
        out.push(Edge { from: r.from.clone(), to: r.to.clone(), why: format!("{}: {}", r.kind, r.why), evidence: ev(r) });
    }
    Ok(out)
}

fn add(e: Edge) -> Result<u64, GraphError> {
    let mut all: Vec<Edge> = std::fs::read_to_string(edges_file()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    if !all.contains(&e) { all.push(e); }
    std::fs::write(edges_file(), serde_json::to_vec(&all).unwrap()).map_err(|e| GraphError::Unavailable(e.to_string()))?;
    Ok(all.len() as u64)
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let me = ce_gate::node_identity().map_err(|e| e.to_string())?;
    let started = Instant::now();
    let gate = ce_gate::Gate::<RefGraph>::new(me.node_id(), ce_gate::mesh_roots()).into_fn();
    Server::<RefGraph>::new(gate)
        .on::<HealthOp, _, _>(move |_: (), _| async move { Ok(Health { ok: true, version: env!("CARGO_PKG_VERSION").into(), uptime_s: started.elapsed().as_secs() }) })
        .on::<Links, _, _>(|q: LinksReq, _| async move { Ok(links(q).await) })
        .on::<Add, _, _>(|e: Edge, _| async move { Ok(add(e)) })
        .serve_door()
        .await
        .map_err(|e| e.to_string())
}
