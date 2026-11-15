// ref.graph@1: what links to what, each edge with its why and the evidence that says it.
api! {
    api RefGraph = "ref.graph", version 1;
    types {
        pub struct Health { pub ok: bool, pub version: String, pub uptime_s: u64 }
        pub enum Dir { Out, In, Both }
        pub struct LinksReq { pub reference: String, pub dir: Dir, pub depth: u32 }
        pub struct Edge { pub from: String, pub to: String, pub why: String, pub evidence: String }
        pub enum GraphError { Invalid(String), Unavailable(String) }
    }
    ops {
        1 => HealthOp(()) -> Health, needs "ref.graph:health";
        2 => Links(LinksReq) -> Result<Vec<Edge>, GraphError>, needs "ref.graph:read";
        3 => Add(Edge) -> Result<u64, GraphError>, needs "ref.graph:write";
    }
}
