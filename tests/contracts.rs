//! The contracts: every op has a right of its own api, and the ids the sim uses are typed.
use refs_api::*;

#[test]
fn every_op_needs_a_right_of_its_api() {
    let c = contracts();
    assert_eq!(c.len(), 5);
    for (name, ver, schema, ops) in c {
        assert_eq!(ver, 1);
        assert_ne!(schema, 0);
        assert_eq!(ops[0], (1, "HealthOp"), "{name}: op 1 is the health contract");
        for (_, op) in ops {
            assert!(right_of(name, op).unwrap().starts_with(&format!("{name}:")));
        }
    }
    assert_eq!(right_of("erp.orders", "GetOrder").as_deref(), Some("erp.orders:GetOrder"));
    assert!(right_of("erp.orders", "DeleteAll").is_none());
}

#[test]
fn records_hold_typed_refs() {
    use ce_ref_id::typed::*;
    let a = refs_catalog::Asset { id: "a".into(), title: "t".into(), file: "ce-blob:sha256:3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51".into(), pinned: None, owner: "person:leif".into() };
    assert!(Typed::<FileK>::parse(&a.file).is_ok());
    assert!(Typed::<PersonK>::parse(&a.owner).is_ok());
    assert!(Typed::<PersonK>::parse(&a.file).is_err());
}
