//! The same contract files as the sim (`contracts/`), compiled by `ce_wire::api!`.
pub mod ref_resolve { use ce_wire::api; include!("../../../contracts/ref_resolve.rs"); }
pub mod ref_pin { use ce_wire::api; include!("../../../contracts/ref_pin.rs"); }
pub mod ref_graph { use ce_wire::api; include!("../../../contracts/ref_graph.rs"); }
pub mod refs_catalog { use ce_wire::api; include!("../../../contracts/refs_catalog.rs"); }
pub mod erp_orders { use ce_wire::api; include!("../../../contracts/erp_orders.rs"); }
