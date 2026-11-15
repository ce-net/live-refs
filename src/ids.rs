//! The id proof of a run: the Rust ids against the reference implementation's answers (vectors written by
//! ce-ref's portable.py and ce_ref.py, checked live by crates/ce-ref-id/tests/interop.rs), and against the
//! second Rust implementation inside CAL (ce-net-proto `cal::refs`), which compiles the grants of this run.
use serde_json::{json, Value};

pub fn identity() -> Value {
    let doc: Value = serde_json::from_str(include_str!("../crates/ce-ref-id/vectors/ids.json")).unwrap();
    let (inp, ans) = (&doc["inputs"], &doc["answers"]);
    let s = |v: &Value| v.as_str().unwrap().to_string();
    let (mut same, mut total, mut cal_same, mut cal_total) = (0, 0, 0, 0);
    let mut cal_differs: Vec<Value> = vec![];
    for (i, o) in inp["origins"].as_array().unwrap().iter().enumerate() {
        let r = ce_ref_id::origin_id(&s(o)).ok().map(|(a, b)| json!([a, b])).unwrap_or(Value::Null);
        total += 1;
        same += (r == ans["origins"][i]) as u32;
        let c = ce_net_proto::cal::refs::origin_id(&s(o)).ok().map(|(a, b)| json!([a, b])).unwrap_or(Value::Null);
        cal_total += 1;
        cal_same += (c == r) as u32;
        if c != r { cal_differs.push(json!({"input": o.clone(), "python_and_ce_ref_id": r, "cal": c})); }
    }
    for (i, p) in inp["references"].as_array().unwrap().iter().enumerate() {
        let r = ce_ref_id::reference(&s(&p[0]), &s(&p[1])).ok().map(Value::from).unwrap_or(Value::Null);
        total += 1;
        same += (r == ans["references"][i]) as u32;
        let c = ce_net_proto::cal::refs::portable(&s(&p[0]), &s(&p[1])).ok().map(Value::from).unwrap_or(Value::Null);
        cal_total += 1;
        cal_same += (c == r) as u32;
        if c != r { cal_differs.push(json!({"input": p.clone(), "python_and_ce_ref_id": r, "cal": c})); }
    }
    for (i, p) in inp["portables"].as_array().unwrap().iter().enumerate() {
        let r = ce_ref_id::parse_portable(&s(p)).ok().map(|(a, b)| json!([a, b])).unwrap_or(Value::Null);
        total += 1;
        same += (r == ans["portables"][i]) as u32;
        let c = ce_net_proto::cal::refs::parse_portable(&s(p)).ok().map(|(a, b)| json!([a, b])).unwrap_or(Value::Null);
        cal_total += 1;
        cal_same += (c == r) as u32;
        if c != r { cal_differs.push(json!({"input": p.clone(), "python_and_ce_ref_id": r, "cal": c})); }
    }
    for (i, p) in inp["named"].as_array().unwrap().iter().enumerate() {
        let r = ce_ref_id::parse_named(&s(p)).ok().map(|x| json!([x.kind, x.target, x.version, x.fragment])).unwrap_or(Value::Null);
        total += 1;
        same += (r == ans["named"][i]) as u32;
    }
    json!({"python_vectors": {"same": same, "of": total}, "cal_rust": {"same": cal_same, "of": cal_total, "differs": cal_differs},
           "summary": format!("{same} of {total} against the Python, {cal_same} of {cal_total} against CAL's Rust")})
}
