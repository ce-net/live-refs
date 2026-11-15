//! `api!` with the grammar of `ce_wire::api!`. A contract file under `contracts/` is written once and compiled by
//! both: by this crate for the sim mesh (no private crates needed), and by `ce_wire` itself in `cells/` for the
//! real door. The schema hash is computed the same way (fnv64 over the same token text), so the proof can show
//! that the sim and the live cell speak one contract.

pub use serde;

pub const fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    h
}

#[derive(Debug, Clone, Copy)]
pub struct OpShape {
    pub id: u32,
    pub name: &'static str,
    pub req: &'static str,
    pub resp: &'static str,
}

pub trait Api: 'static {
    const NAME: &'static str;
    const VERSION: u32;
    const SCHEMA: u64;
    const RIGHTS: &'static [&'static str];
    const OPS: &'static [OpShape];
}

pub trait Op {
    type Api: Api;
    const ID: u32;
    const NAME: &'static str;
    const RIGHT: &'static str;
    type Req: serde::Serialize + serde::de::DeserializeOwned;
    type Resp: serde::Serialize + serde::de::DeserializeOwned;
}

#[macro_export]
macro_rules! api {
    (
        api $api:ident = $name:literal, version $ver:literal $(, accepts [ $($acc:literal),* $(,)? ])? ;
        types { $($ty:item)* }
        ops { $( $id:literal => $op:ident ( $req:ty ) -> $resp:ty , needs $right:literal $(, $okw:ident $($oval:literal)?)* ; )* }
    ) => {
        $(
            #[derive($crate::serde::Serialize, $crate::serde::Deserialize, Clone, PartialEq, Debug)]
            #[serde(crate = "wire_lite::serde")]
            $ty
        )*
        pub struct $api;
        impl $crate::Api for $api {
            const NAME: &'static str = $name;
            const VERSION: u32 = $ver;
            const SCHEMA: u64 = $crate::fnv64(concat!(
                $name, "/", stringify!($ver), "|", stringify!($($ty)*),
                $( "|", stringify!($id), " ", stringify!($op), "(", stringify!($req), ")->", stringify!($resp), " ", $right, )*
            ).as_bytes());
            const RIGHTS: &'static [&'static str] = &[$($right,)*];
            const OPS: &'static [$crate::OpShape] = &[
                $( $crate::OpShape { id: $id, name: stringify!($op), req: stringify!($req), resp: stringify!($resp) }, )*
            ];
        }
        $(
            pub struct $op;
            impl $crate::Op for $op {
                type Api = $api;
                const ID: u32 = $id;
                const NAME: &'static str = stringify!($op);
                const RIGHT: &'static str = $right;
                type Req = $req;
                type Resp = $resp;
            }
        )*
    };
}
