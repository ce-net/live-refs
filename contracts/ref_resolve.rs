// ref.resolve@1: where a ref lives now. One file, compiled by wire-lite (sim) and by ce_wire (cells/).
api! {
    api RefResolve = "ref.resolve", version 1;
    types {
        /// Health contract: these three fields, in this order, in every cell.
        pub struct Health { pub ok: bool, pub version: String, pub uptime_s: u64 }
        pub struct ResolveReq { pub reference: String }
        /// One place the thing is now: the node, its key, and what it holds there (a content hash for bytes).
        pub struct Holder { pub node: String, pub node_key: String, pub sha256: Option<String>, pub size: u64, pub since_ms: u64, pub live: bool }
        /// `source` is "mesh" when a holder answered now, "local index" when none could be reached; `as_of_ms` is
        /// then the time of the newest announcement the local index holds.
        pub struct Located { pub id: String, pub kind: String, pub holders: Vec<Holder>, pub pin: Option<String>, pub source: String, pub as_of_ms: u64, pub detail: String }
        pub enum Resolution { Located(Located), Ambiguous { written: String, reason: String, candidates: Vec<String> }, Unknown { written: String, reason: String } }
        pub struct Announce { pub id: String, pub kind: String, pub node: String, pub sha256: Option<String>, pub size: u64, pub at_ms: u64, pub gone: bool, pub detail: String }
        pub enum RefError { Invalid(String), Unavailable(String) }
    }
    ops {
        1 => HealthOp(()) -> Health, needs "ref.resolve:health";
        2 => Resolve(ResolveReq) -> Result<Resolution, RefError>, needs "ref.resolve:read";
        3 => Publish(Announce) -> Result<u64, RefError>, needs "ref.resolve:announce";
    }
}
