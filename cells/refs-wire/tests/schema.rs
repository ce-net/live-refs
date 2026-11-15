//! One contract, two compilers: ce_wire::api! (live) and wire_lite::api! (sim) give the same name, version, ops,
//! rights and schema hash, so the sim and the real door speak the same contract.
macro_rules! same { ($m:ident, $t:ident) => {{
    use ce_wire::Api as W; use refs_api::Api as L;
    assert_eq!(<refs_wire::$m::$t as W>::NAME, <refs_api::$m::$t as L>::NAME);
    assert_eq!(<refs_wire::$m::$t as W>::VERSION, <refs_api::$m::$t as L>::VERSION);
    assert_eq!(<refs_wire::$m::$t as W>::RIGHTS, <refs_api::$m::$t as L>::RIGHTS);
    assert_eq!(<refs_wire::$m::$t as W>::SCHEMA, <refs_api::$m::$t as L>::SCHEMA, "schema hash of {}", stringify!($t));
}} }
#[test]
fn sim_and_live_contracts_are_one() {
    same!(ref_resolve, RefResolve);
    same!(ref_pin, RefPin);
    same!(ref_graph, RefGraph);
    same!(refs_catalog, RefsCatalog);
    same!(erp_orders, ErpOrders);
}
