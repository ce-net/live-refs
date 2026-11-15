//! The contracts in `contracts/`, compiled with `wire_lite::api!`. `cells/` compiles the same files with
//! `ce_wire::api!`; `tests/schema.rs` there checks the schema hashes are equal.
pub use wire_lite::{Api, Op};
pub mod ref_resolve { use wire_lite::api; include!("../../../contracts/ref_resolve.rs"); }
pub mod ref_pin { use wire_lite::api; include!("../../../contracts/ref_pin.rs"); }
pub mod ref_graph { use wire_lite::api; include!("../../../contracts/ref_graph.rs"); }
pub mod refs_catalog { use wire_lite::api; include!("../../../contracts/refs_catalog.rs"); }
pub mod erp_orders { use wire_lite::api; include!("../../../contracts/erp_orders.rs"); }

/// Every api this repo defines: (name, version, schema hash, ops as (id, name, right)).
pub fn contracts() -> Vec<(&'static str, u32, u64, Vec<(u32, &'static str)>)> {
    fn c<A: Api>() -> (&'static str, u32, u64, Vec<(u32, &'static str)>) {
        (A::NAME, A::VERSION, A::SCHEMA, A::OPS.iter().map(|o| (o.id, o.name)).collect())
    }
    vec![c::<ref_resolve::RefResolve>(), c::<ref_pin::RefPin>(), c::<ref_graph::RefGraph>(), c::<refs_catalog::RefsCatalog>(), c::<erp_orders::ErpOrders>()]
}

/// The right an op of `api` needs, from the contract (None: no such op).
pub fn right_of(api: &str, op: &str) -> Option<String> {
    let all: [(&str, &[wire_lite::OpShape], &[&str]); 5] = [
        (ref_resolve::RefResolve::NAME, ref_resolve::RefResolve::OPS, ref_resolve::RefResolve::RIGHTS),
        (ref_pin::RefPin::NAME, ref_pin::RefPin::OPS, ref_pin::RefPin::RIGHTS),
        (ref_graph::RefGraph::NAME, ref_graph::RefGraph::OPS, ref_graph::RefGraph::RIGHTS),
        (refs_catalog::RefsCatalog::NAME, refs_catalog::RefsCatalog::OPS, refs_catalog::RefsCatalog::RIGHTS),
        (erp_orders::ErpOrders::NAME, erp_orders::ErpOrders::OPS, erp_orders::ErpOrders::RIGHTS),
    ];
    let (_, ops, rights) = all.iter().find(|(n, _, _)| *n == api)?;
    ops.iter().position(|o| o.name == op).map(|i| rights[i].to_string())
}
