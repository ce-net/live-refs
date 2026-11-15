//! The whole walk, end to end: four node processes, eight steps, and the proof checked.
use serde_json::Value;

#[test]
fn the_walk_proves_every_claim() {
    let out = std::env::temp_dir().join(format!("live-refs-test-{}", std::process::id()));
    let st = std::process::Command::new(env!("CARGO_BIN_EXE_live-refs")).args(["sim", "--out"]).arg(&out).status().unwrap();
    assert!(st.success());
    let n: Value = serde_json::from_str(&std::fs::read_to_string(out.join("summary.json")).unwrap()).unwrap();
    assert_eq!(n["kinds_resolved"], "9 of 9");
    assert_eq!(n["move"]["converged"], true);
    assert_eq!(n["move"]["same_id"], true);
    assert_eq!(n["move"]["after"], serde_json::json!(["server"]));
    assert_eq!(n["tamper_refusals"], "2 of 2");
    assert_eq!(n["grant"]["allowed"], true);
    assert_eq!(n["grant"]["other_op_refused"], true);
    assert_eq!(n["grant"]["tampered_refused"], true);
    assert_eq!(n["record"]["file_on"], serde_json::json!(["phone"]));
    assert_eq!(n["record"]["bytes_ok"], true);
    for k in ["has_grant", "has_commit", "has_reader", "has_row"] {
        assert_eq!(n["graph"][k], true, "{k}");
    }
    assert_eq!(n["offline"]["resolved"], 3);
    assert_eq!(n["offline"]["after_heal"], "mesh");
    assert_eq!(n["ambiguity"]["refused"], 1);
    assert_eq!(n["ambiguity"]["accepted"], 1);
    assert_eq!(n["ids"]["python_vectors"]["same"], n["ids"]["python_vectors"]["of"]);
    let v = std::process::Command::new(env!("CARGO_BIN_EXE_live-refs")).arg("verify").arg(&out).output().unwrap();
    assert!(v.status.success(), "{}", String::from_utf8_lossy(&v.stderr));
    // A changed step is found.
    let j = std::fs::read_to_string(out.join("run.jsonl")).unwrap().replacen("\"refused\"", "\"ok\"", 1);
    std::fs::write(out.join("run.jsonl"), j).unwrap();
    let v = std::process::Command::new(env!("CARGO_BIN_EXE_live-refs")).arg("verify").arg(&out).output().unwrap();
    assert!(!v.status.success());
    let _ = std::fs::remove_dir_all(&out);
}
