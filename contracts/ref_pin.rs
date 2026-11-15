// ref.pin@1: pin a ref to its content hash, verify it, fetch only the pinned bytes.
api! {
    api RefPin = "ref.pin", version 1;
    types {
        pub struct Health { pub ok: bool, pub version: String, pub uptime_s: u64 }
        pub struct PinReq { pub reference: String }
        pub struct PinnedRef { pub reference: String, pub sha256: String, pub size: u64, pub node: String }
        pub struct VerifyReq { pub pinned: String }
        pub enum Verdict { Ok { sha256: String }, Refused { want: String, got: String } }
        pub struct FetchReq { pub pinned: String }
        pub enum Fetched { Ok { sha256: String, bytes: Vec<u8> }, Refused { want: String, got: String } }
        pub struct PutReq { pub id: String, pub bytes: Vec<u8> }
        pub enum PinError { Invalid(String), NotHere(String) }
    }
    ops {
        1 => HealthOp(()) -> Health, needs "ref.pin:health";
        2 => Pin(PinReq) -> Result<PinnedRef, PinError>, needs "ref.pin:read";
        3 => Verify(VerifyReq) -> Result<Verdict, PinError>, needs "ref.pin:read";
        4 => Fetch(FetchReq) -> Result<Fetched, PinError>, needs "ref.pin:read";
        5 => Put(PutReq) -> Result<PinnedRef, PinError>, needs "ref.pin:write";
    }
}
