// erp.orders@1: an ordinary order system (an HTTP program that knows nothing of the mesh), wrapped as a cell.
api! {
    api ErpOrders = "erp.orders", version 1;
    types {
        pub struct Health { pub ok: bool, pub version: String, pub uptime_s: u64 }
        /// `grant` is a cap v3 token (hex) the caller presents, `program` the id of the program it binds, `report` the pinned
        /// file that program runs.
        pub struct OrderReq { pub id: String, pub grant: String, pub program: String, pub report: String }
        pub struct Order { pub id: String, pub customer: String, pub total_cents: u64, pub status: String, pub served_by: String }
        pub enum ErpError { Refused(String), NotFound(String), Unavailable(String) }
    }
    ops {
        1 => HealthOp(()) -> Health, needs "erp.orders:health";
        2 => GetOrder(OrderReq) -> Result<Order, ErpError>, needs "erp.orders:GetOrder";
        3 => ListOrders(OrderReq) -> Result<Vec<String>, ErpError>, needs "erp.orders:ListOrders";
    }
}
