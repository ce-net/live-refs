//! Byte-identity of every id against the reference implementation.
//!
//! `vectors/ids.json` holds what ce-ref's `portable.py` and `ce_ref.py parse` answer for each input. The test
//! always checks the Rust answers against that file. When a ce-ref checkout is present (`CE_REF_DIR`, default
//! `~/dev/ce-ref`) it also runs the Python itself on the same inputs and requires the same bytes, so the file can
//! never drift from the code; `CE_REF_WRITE=1` rewrites the file from the Python.

use ce_ref_id::*;
use serde_json::{json, Value};
use std::path::PathBuf;

fn inputs() -> Value {
    json!({
        "origins": [
            "https://github.com/ce-net/ce-ref", "https://github.com/ce-net/ce-ref.git", "https://GitHub.com/CE-Net/CE-Ref.git/",
            "git@github.com:ce-net/ce-ref.git", "ssh://git@github.com/ce-net/ce-ref.git", "https://gitlab.example.org/Team/Repo.git",
            "https://github.com:443/ce-net/ce-ref", "https://user@github.com/a/b", "https://user:pw@github.com/a/b",
            "http://github.com/a/b", "https://github.com/a/b?x=1", "https://github.com/a/b#f", "https://github.com/",
            "https://github.com/a/../b", "https://github.com/a/b%20c", "git@bad host:a/b", "git@github.com:a b",
            "ssh://root@host/a", "  https://github.com/a/b", "https://github.com/a/\tb", "HTTPS://Example.COM/A/B",
            "https://[::1]/a/b", "https://example.org/a/b.git.git", "file:///tmp/x", "github.com/a/b",
            "https://github.com/example/huey-scripts", "https://github.com/leif-rydenfalk/notes", "https://erp.corp.example/finance/orders.git"
        ],
        "references": [
            ["b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331", "run.py"],
            ["b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331", "docs/a b/ü.md"],
            ["b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331", "a//b/"],
            ["b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331", "a/./b"],
            ["b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331", "../x"],
            ["b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331", "/abs"],
            ["b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331", "x?y#z&%+=~"],
            ["B47AE72900538D9D902251C935592073814514E0A5DB7F31B4731A2FC046F331", "run.py"],
            ["b47ae729", "run.py"],
            ["b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331", ""]
        ],
        "portables": [
            "ce-ref://repo/b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331/run.py",
            "ce-ref://repo/b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331/docs/a%20b/%C3%BC.md",
            "ce-ref://repo/b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331/a%2Fb",
            "ce-ref://repo/b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331",
            "ce-ref://repo/b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331/x?y",
            "ce-ref://repo/b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331/%2E%2E/x",
            "ce-ref://node/b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331/x",
            "ce-ref://repo/xyz/x"
        ],
        "named": [
            "doc:ce-ref/docs/GLOBAL-FILES", "part:motor-mount@v1.2.3", "part:motor-mount@v1.2", "endpoint:app/api#ops",
            "repo:ce-ref", "media:3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51", "run.py", "Doc:x",
            "doc:.hidden", "  skill:ce-ref  ", "port:7700", "doc:a b", "a-b:c#", "x:y@v1.2.3#frag#2"
        ]
    })
}

fn rust_answers(inp: &Value) -> Value {
    let s = |v: &Value| v.as_str().unwrap().to_string();
    let origins: Vec<Value> = inp["origins"].as_array().unwrap().iter().map(|o| match origin_id(&s(o)) {
        Ok((id, c)) => json!([id, c]),
        Err(_) => json!(null),
    }).collect();
    let refs: Vec<Value> = inp["references"].as_array().unwrap().iter().map(|p| match reference(&s(&p[0]), &s(&p[1])) {
        Ok(r) => json!(r),
        Err(_) => json!(null),
    }).collect();
    let ports: Vec<Value> = inp["portables"].as_array().unwrap().iter().map(|p| match parse_portable(&s(p)) {
        Ok((r, path)) => json!([r, path]),
        Err(_) => json!(null),
    }).collect();
    let named: Vec<Value> = inp["named"].as_array().unwrap().iter().map(|p| match parse_named(&s(p)) {
        Ok(x) => json!([x.kind, x.target, x.version, x.fragment]),
        Err(_) => json!(null),
    }).collect();
    json!({"origins": origins, "references": refs, "portables": ports, "named": named})
}

/// The reference implementation's answers, by running it. The Python here only calls ce-ref's own functions.
fn python_answers(dir: &PathBuf, inp: &Value) -> Option<Value> {
    if !dir.join("portable.py").exists() || !dir.join("ce_ref.py").exists() {
        return None;
    }
    let prog = r#"
import json,sys,portable,ce_ref
inp=json.load(sys.stdin)
def t(f):
    try: return f()
    except ValueError: return None
out={"origins":[t(lambda o=o: list(portable.origin_id(o))) for o in inp["origins"]],
     "references":[t(lambda p=p: portable.reference(p[0],p[1])) for p in inp["references"]],
     "portables":[t(lambda p=p: list(portable.parse(p))) for p in inp["portables"]],
     "named":[(lambda r: None if r[4] else [r[0],r[1],r[2],r[3]])(ce_ref.parse(n)) for n in inp["named"]]}
sys.stdout.write(json.dumps(out,ensure_ascii=False))
"#;
    use std::io::Write;
    let mut c = std::process::Command::new("python3")
        .arg("-c").arg(prog).current_dir(dir).env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().ok()?;
    c.stdin.take().unwrap().write_all(inp.to_string().as_bytes()).ok()?;
    let o = c.wait_with_output().ok()?;
    assert!(o.status.success(), "python failed: {}", String::from_utf8_lossy(&o.stderr));
    Some(serde_json::from_slice(&o.stdout).expect("python json"))
}

#[test]
fn byte_identical_to_reference() {
    let inp = inputs();
    let vf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors/ids.json");
    let dir = std::env::var_os("CE_REF_DIR").map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join("dev/ce-ref"));
    let rust = rust_answers(&inp);
    if let Some(py) = python_answers(&dir, &inp) {
        if std::env::var("CE_REF_WRITE").is_ok() {
            let doc = json!({"about": "answers of ce-ref portable.py and ce_ref.py parse for these inputs (null = refused)", "inputs": inp, "answers": py});
            std::fs::write(&vf, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        }
        for k in ["origins", "references", "portables", "named"] {
            for (i, (a, b)) in py[k].as_array().unwrap().iter().zip(rust[k].as_array().unwrap()).enumerate() {
                assert_eq!(a, b, "{k}[{i}] {} : python vs rust", inp[k][i]);
            }
        }
        eprintln!("checked against the running Python in {}", dir.display());
    }
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&vf).expect("vectors/ids.json")).unwrap();
    assert_eq!(doc["inputs"], inp, "vectors were written for other inputs: rerun with CE_REF_WRITE=1");
    let mut n = 0;
    for k in ["origins", "references", "portables", "named"] {
        for (i, (a, b)) in doc["answers"][k].as_array().unwrap().iter().zip(rust[k].as_array().unwrap()).enumerate() {
            assert_eq!(a, b, "{k}[{i}] {} : vector vs rust", inp[k][i]);
            n += 1;
        }
    }
    assert_eq!(n, 60);
}
