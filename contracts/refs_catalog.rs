// refs.catalog@1: records that point at things anywhere (an Asset row on one node naming a file on another).
api! {
    api RefsCatalog = "refs.catalog", version 1;
    types {
        pub struct Health { pub ok: bool, pub version: String, pub uptime_s: u64 }
        /// `file` is a file ref, `pinned` the same file with its content hash, `owner` a person ref.
        pub struct Asset { pub id: String, pub title: String, pub file: String, pub pinned: Option<String>, pub owner: String }
        pub enum CatalogError { Invalid(String), NotFound(String) }
    }
    ops {
        1 => HealthOp(()) -> Health, needs "refs.catalog:health";
        2 => Insert(Asset) -> Result<u64, CatalogError>, needs "refs.catalog:write";
        3 => Get(String) -> Result<Asset, CatalogError>, needs "refs.catalog:read";
    }
}
