//! ce-ref ids in Rust. Every id form is byte-identical to the reference implementation
//! (`ce-ref` `portable.py` and `ce_ref.py parse`, and the pinned forms of CAL, `ce-net-proto` docs/CAL.md section 3):
//!
//! | Kind | Form |
//! |---|---|
//! | file (portable) | `ce-ref://repo/<sha256 of the normalized git origin>/<path>` |
//! | repo path at a commit | `repo:<repo>/<path>@<commit> sha256:<hash>` |
//! | blob | `ce-blob:sha256:<hash>` |
//! | node | `node:<name>` or `node:<64 hex>` |
//! | person, agent | `person:<id> ed25519:<64 hex>`, `agent:<lane> ed25519:<64 hex>` (the key is the pin) |
//! | cell op | `cell:<api>@<major>` and `cell:<api>@<major>#<Op>` |
//! | capability | `cap:<64 hex link id>` |
//! | any other kind | `kind:target[@vX.Y.Z][#fragment]` (`ce_ref.py`) |
//!
//! The crate has no dependencies besides `sha2`, so any cell can use it.

use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
fn err<T>(s: &str) -> Result<T, Error> {
    Err(Error(s.to_string()))
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

// ---------------------------------------------------------------- portable.py

/// Python `urlsplit` input cleaning: leading C0/space stripped, then tab, CR and LF removed.
fn url_clean(s: &str) -> String {
    s.trim_start_matches(|c: char| c <= ' ').chars().filter(|c| !matches!(c, '\t' | '\r' | '\n')).collect()
}

/// `portable.origin_id`: (sha256 hex of the canonical origin, canonical origin).
pub fn origin_id(origin: &str) -> Result<(String, String), Error> {
    let (host, path): (String, String) = if origin.starts_with("git@") {
        // re.fullmatch(r'git@([A-Za-z0-9.-]+):([^\s]+)')
        let rest = &origin[4..];
        let Some(colon) = rest.find(':') else { return err("unsupported Git origin") };
        let (h, p) = (&rest[..colon], &rest[colon + 1..]);
        let host_ok = !h.is_empty() && h.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-');
        if !host_ok || p.is_empty() || p.chars().any(py_space) {
            return err("unsupported Git origin");
        }
        (h.to_string(), p.to_string())
    } else {
        let u = url_clean(origin);
        let (scheme, rest) = match u.find(':') {
            Some(i) if is_scheme(&u[..i]) => (u[..i].to_ascii_lowercase(), &u[i + 1..]),
            _ => (String::new(), u.as_str()),
        };
        let bad = || err("origin must be an uncredentialed HTTPS/SSH Git URL");
        let (netloc, after) = match rest.strip_prefix("//") {
            Some(r) => {
                let end = r.find(['/', '?', '#']).unwrap_or(r.len());
                (&r[..end], &r[end..])
            }
            None => ("", rest),
        };
        let (path_q, frag) = match after.find('#') {
            Some(i) => (&after[..i], Some(&after[i + 1..])),
            None => (after, None),
        };
        let (upath, query) = match path_q.find('?') {
            Some(i) => (&path_q[..i], Some(&path_q[i + 1..])),
            None => (path_q, None),
        };
        let (userinfo, hostport) = match netloc.rfind('@') {
            Some(i) => (Some(&netloc[..i]), &netloc[i + 1..]),
            None => (None, netloc),
        };
        let (username, password) = match userinfo {
            Some(ui) => match ui.find(':') {
                Some(i) => (Some(&ui[..i]), Some(&ui[i + 1..])),
                None => (Some(ui), None),
            },
            None => (None, None),
        };
        let hostname = if let Some(b) = hostport.strip_prefix('[') {
            b.split(']').next().unwrap_or("").to_lowercase()
        } else {
            hostport.split(':').next().unwrap_or("").to_lowercase()
        };
        let nonempty = |o: Option<&str>| o.is_some_and(|s| !s.is_empty());
        if (scheme != "https" && scheme != "ssh") || hostname.is_empty() || password.is_some() || nonempty(query) || nonempty(frag) {
            return bad();
        }
        if let Some(un) = username {
            if !(scheme == "ssh" && un == "git") {
                return err("credential-bearing origin refused");
            }
        }
        (hostname, upath.trim_start_matches('/').to_string())
    };
    let path = path.strip_suffix(".git").unwrap_or(&path).trim_matches('/').to_string();
    if path.is_empty() || path.split('/').any(|s| s == "..") || path.contains(['?', '%', '#', '\\']) {
        return err("invalid origin path");
    }
    let mut canonical = format!("{}/{}", host.to_lowercase(), path);
    if host.to_lowercase() == "github.com" {
        canonical = canonical.to_lowercase();
    }
    Ok((sha256_hex(canonical.as_bytes()), canonical))
}

fn is_scheme(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b[0].is_ascii_alphabetic() && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
}

/// Python `str.isspace` / regex `\s` for str.
fn py_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// `portable.safe_path`: a normalized relative POSIX path.
pub fn safe_path(path: &str) -> Result<String, Error> {
    if path.is_empty() || path.starts_with('/') || path.split('/').any(|x| x == ".." || x == ".") || path.contains('\\') || path.contains('\0') {
        return err("unsafe relative path");
    }
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    Ok(if parts.is_empty() { ".".into() } else { parts.join("/") })
}

/// Python `urllib.parse.quote(s, safe='/')`.
pub fn quote(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~' | b'/') {
            o.push(b as char)
        } else {
            o.push_str(&format!("%{b:02X}"))
        }
    }
    o
}

/// Python `unquote` (UTF-8, invalid sequences replaced).
pub fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
            let v = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap(), 16).unwrap();
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `portable.reference`: `ce-ref://repo/<repo id>/<quoted path>`.
pub fn reference(repo: &str, path: &str) -> Result<String, Error> {
    if !is_hex64(repo) {
        return err("invalid repository identity");
    }
    Ok(format!("ce-ref://repo/{repo}/{}", quote(&safe_path(path)?)))
}

/// `portable.parse`: (repo id, path).
pub fn parse_portable(r: &str) -> Result<(String, String), Error> {
    let bad = || err("invalid portable reference");
    let Some(rest) = r.strip_prefix("ce-ref://") else { return bad() };
    if rest.contains(['?', '#']) {
        return bad();
    }
    let Some(path) = rest.strip_prefix("repo") else { return bad() };
    if !(path.is_empty() || path.starts_with('/')) {
        return bad();
    }
    let p = path.trim_start_matches('/');
    let (repo, sep, rel) = match p.find('/') {
        Some(i) => (&p[..i], true, &p[i + 1..]),
        None => (p, false, ""),
    };
    if !sep || !is_hex64(repo) {
        return err("invalid repository identity");
    }
    Ok((repo.to_string(), safe_path(&unquote(rel))?))
}

// ---------------------------------------------------------------- ce_ref.py parse

/// `ce_ref.parse`: kind, target, iteration pin, fragment. Same acceptance as the Python regex.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Parsed {
    pub kind: String,
    pub target: String,
    pub version: Option<String>,
    pub fragment: Option<String>,
}

pub fn parse_named(r: &str) -> Result<Parsed, Error> {
    let s = r.trim_matches(py_space);
    let bad = || Err(Error(format!("not a ref: expected kind:target[@vX.Y.Z][#fragment], got {s:?}")));
    let Some(colon) = s.find(':') else { return bad() };
    let kind = &s[..colon];
    let kb = kind.as_bytes();
    if kb.is_empty() || !kb[0].is_ascii_lowercase() || !kb.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-') {
        return bad();
    }
    let rest = &s[colon + 1..];
    let first = rest.chars().next();
    if !first.is_some_and(|c| c.is_ascii_alphanumeric()) {
        return bad();
    }
    let tend = rest.find(|c: char| py_space(c) || c == '@' || c == '#').unwrap_or(rest.len());
    let target = &rest[..tend];
    let mut tail = &rest[tend..];
    let mut version = None;
    if let Some(t) = tail.strip_prefix('@') {
        let end = t.find('#').unwrap_or(t.len());
        let v = &t[..end];
        let ok = v.strip_prefix('v').is_some_and(|n| {
            let p: Vec<&str> = n.split('.').collect();
            p.len() == 3 && p.iter().all(|x| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit()))
        });
        if !ok {
            return bad();
        }
        version = Some(v.to_string());
        tail = &t[end..];
    }
    let mut fragment = None;
    if let Some(f) = tail.strip_prefix('#') {
        if f.is_empty() || f.chars().any(py_space) {
            return bad();
        }
        fragment = Some(f.to_string());
        tail = "";
    }
    if !tail.is_empty() {
        return bad();
    }
    Ok(Parsed { kind: kind.into(), target: target.into(), version, fragment })
}

// ---------------------------------------------------------------- typed refs

/// What a ref names. `Ref` holds the written form; [`Ref::is_pinned`] says whether it names exactly one thing
/// wherever it is read (a content hash, a full id or a key).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ref {
    /// `ce-ref://repo/<repo id>/<path>`, optionally followed by ` sha256:<hash>`.
    File { repo_id: String, path: String, sha256: Option<String> },
    /// `repo:<repo>/<path>@<commit>`, optionally ` sha256:<hash>`.
    RepoAt { repo: String, path: String, commit: String, sha256: Option<String> },
    /// `ce-blob:sha256:<hash>`.
    Blob { sha256: String },
    /// `node:<name>` or `node:<64 hex>`, optionally ` ed25519:<64 hex>`.
    Node { name: String, key: Option<String> },
    /// `person:<id>` / `agent:<lane>`, optionally ` ed25519:<64 hex>`.
    Principal { kind: Principal, id: String, key: Option<String> },
    /// `cell:<api>@<major>` or `cell:<api>@<major>#<Op>`.
    Cell { api: String, major: u32, op: Option<String> },
    /// `cap:<64 hex link id>`.
    Cap { id: String },
    /// A bare name such as `run.py`: never a ref; kept so the refusal can say what was written.
    Bare(String),
    /// Any other `kind:target[@vX.Y.Z][#fragment]` (ce_ref.py kinds: doc, repo, app, endpoint, ...).
    Named(Parsed),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Principal {
    Person,
    Agent,
}

/// The nine kinds a live system shows (and `Other`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    File,
    RepoAt,
    Blob,
    Node,
    Person,
    Agent,
    CellOp,
    Cap,
    Cell,
    Bare,
    Other,
}

fn key_ok(k: &str) -> bool {
    k.strip_prefix("ed25519:").is_some_and(is_hex64) || k.strip_prefix("p256:").is_some_and(|h| h.len() == 66 && h.bytes().all(|c| c.is_ascii_hexdigit()))
}
fn sha_of(s: &str) -> Result<String, Error> {
    match s.strip_prefix("sha256:") {
        Some(h) if is_hex64(h) => Ok(h.to_string()),
        Some(h) if h.ends_with('…') || h.len() < 64 => err("a shortened hash: write the whole sha256"),
        _ => err("expected sha256:<64 lowercase hex>"),
    }
}

impl Ref {
    pub fn parse(s: &str) -> Result<Ref, Error> {
        let s = s.trim();
        let mut words = s.split_whitespace();
        let head = words.next().ok_or(Error("empty ref".into()))?;
        let pin = words.next();
        if words.next().is_some() {
            return err("a ref is one name and at most one pin");
        }
        if let Some(rest) = head.strip_prefix("ce-blob:") {
            if pin.is_some() {
                return err("a blob is its own pin");
            }
            return Ok(Ref::Blob { sha256: sha_of(rest)? });
        }
        if head.starts_with("ce-ref://") {
            let (repo_id, path) = parse_portable(head)?;
            return Ok(Ref::File { repo_id, path, sha256: pin.map(sha_of).transpose()? });
        }
        if let Some(rest) = head.strip_prefix("repo:") {
            if let Some((rp, commit)) = rest.rsplit_once('@') {
                let Some((repo, path)) = rp.split_once('/') else { return err("repo:<repo>/<path>@<commit>") };
                if !(4..=40).contains(&commit.len()) || !commit.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
                    return err("a commit is 4 to 40 lowercase hex digits");
                }
                return Ok(Ref::RepoAt { repo: repo.into(), path: safe_path(path)?, commit: commit.into(), sha256: pin.map(sha_of).transpose()? });
            }
        }
        if let Some(rest) = head.strip_prefix("node:") {
            if rest.is_empty() {
                return err("node:<name>");
            }
            if let Some(k) = pin {
                if !k.starts_with("ed25519:") || !key_ok(k) {
                    return err("a node key is ed25519:<64 hex>");
                }
            }
            return Ok(Ref::Node { name: rest.into(), key: pin.map(String::from) });
        }
        for (p, kind) in [("person:", Principal::Person), ("agent:", Principal::Agent)] {
            if let Some(id) = head.strip_prefix(p) {
                if id.is_empty() {
                    return err("a principal needs an id");
                }
                if let Some(k) = pin {
                    if !key_ok(k) {
                        return err("a principal key is ed25519:<64 hex> or p256:<66 hex>");
                    }
                }
                return Ok(Ref::Principal { kind, id: id.into(), key: pin.map(String::from) });
            }
        }
        if let Some(rest) = head.strip_prefix("cell:") {
            let (main, op) = match rest.split_once('#') {
                Some((m, o)) => (m, Some(o.to_string())),
                None => (rest, None),
            };
            let Some((api, major)) = main.rsplit_once('@') else { return err("a cell names its major: cell:<api>@<major>") };
            let major: u32 = major.parse().map_err(|_| Error("the major is an integer".into()))?;
            return Ok(Ref::Cell { api: api.into(), major, op });
        }
        if let Some(id) = head.strip_prefix("cap:") {
            if !is_hex64(id) {
                return err("cap:<64 hex link id>");
            }
            return Ok(Ref::Cap { id: id.into() });
        }
        if pin.is_some() {
            return err("only files, nodes and principals carry a pin");
        }
        match parse_named(head) {
            Ok(p) => Ok(Ref::Named(p)),
            Err(_) if !head.contains(':') => Ok(Ref::Bare(head.into())),
            Err(e) => Err(e),
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Ref::File { .. } => Kind::File,
            Ref::RepoAt { .. } => Kind::RepoAt,
            Ref::Blob { .. } => Kind::Blob,
            Ref::Node { .. } => Kind::Node,
            Ref::Principal { kind: Principal::Person, .. } => Kind::Person,
            Ref::Principal { kind: Principal::Agent, .. } => Kind::Agent,
            Ref::Cell { op: Some(_), .. } => Kind::CellOp,
            Ref::Cell { .. } => Kind::Cell,
            Ref::Cap { .. } => Kind::Cap,
            Ref::Bare(_) => Kind::Bare,
            Ref::Named(_) => Kind::Other,
        }
    }

    /// Names exactly one thing everywhere: a content hash, a full node id, a key, a cell major or a cap id.
    pub fn is_pinned(&self) -> bool {
        match self {
            Ref::File { sha256, .. } | Ref::RepoAt { sha256, .. } => sha256.is_some(),
            Ref::Blob { .. } | Ref::Cap { .. } | Ref::Cell { .. } => true,
            Ref::Node { name, key } => is_hex64(name) || key.is_some(),
            Ref::Principal { key, .. } => key.is_some(),
            Ref::Bare(_) | Ref::Named(_) => false,
        }
    }

    /// The id without its pin: what stays the same when the thing moves or changes.
    pub fn id(&self) -> String {
        match self {
            Ref::File { repo_id, path, .. } => format!("ce-ref://repo/{repo_id}/{}", quote(path)),
            Ref::RepoAt { repo, path, commit, .. } => format!("repo:{repo}/{path}@{commit}"),
            Ref::Blob { sha256 } => format!("ce-blob:sha256:{sha256}"),
            Ref::Node { name, .. } => format!("node:{name}"),
            Ref::Principal { kind: Principal::Person, id, .. } => format!("person:{id}"),
            Ref::Principal { kind: Principal::Agent, id, .. } => format!("agent:{id}"),
            Ref::Cell { api, major, op: None } => format!("cell:{api}@{major}"),
            Ref::Cell { api, major, op: Some(o) } => format!("cell:{api}@{major}#{o}"),
            Ref::Cap { id } => format!("cap:{id}"),
            Ref::Bare(s) => s.clone(),
            Ref::Named(p) => {
                let mut s = format!("{}:{}", p.kind, p.target);
                if let Some(v) = &p.version {
                    s += &format!("@{v}");
                }
                if let Some(f) = &p.fragment {
                    s += &format!("#{f}");
                }
                s
            }
        }
    }

    pub fn pin(&self) -> Option<String> {
        match self {
            Ref::File { sha256: Some(h), .. } | Ref::RepoAt { sha256: Some(h), .. } => Some(format!("sha256:{h}")),
            Ref::Node { key: Some(k), .. } | Ref::Principal { key: Some(k), .. } => Some(k.clone()),
            _ => None,
        }
    }

    pub fn with_sha(&self, h: &str) -> Ref {
        let mut r = self.clone();
        if let Ref::File { sha256, .. } | Ref::RepoAt { sha256, .. } = &mut r {
            *sha256 = Some(h.to_string());
        }
        r
    }
}

impl fmt::Display for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pin() {
            Some(p) => write!(f, "{} {}", self.id(), p),
            None => f.write_str(&self.id()),
        }
    }
}

impl std::str::FromStr for Ref {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        Ref::parse(s)
    }
}

/// The portable file ref for a file in the repository whose git origin is `origin`.
pub fn file_ref(origin: &str, path: &str) -> Result<Ref, Error> {
    let (repo_id, _) = origin_id(origin)?;
    Ok(Ref::File { repo_id, path: safe_path(path)?, sha256: None })
}

/// `ce-blob:sha256:<hash>` of these bytes.
pub fn blob_ref(bytes: &[u8]) -> Ref {
    Ref::Blob { sha256: sha256_hex(bytes) }
}

/// Typed refs: `Ref<K>` is checked to be of kind `K` when it is made, so a function that takes `Typed<FileK>`
/// cannot be handed a node. `ce_ref!("...")` makes one from a literal and panics at first use if it does not
/// parse; the literal is checked by the test suite of every crate that uses it.
pub mod typed {
    use super::*;
    use std::marker::PhantomData;
    pub trait RefKind {
        const NAME: &'static str;
        fn accepts(k: Kind) -> bool;
    }
    macro_rules! kinds { ($($n:ident = $s:literal: $($k:ident)|+;)*) => { $(
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub struct $n;
        impl RefKind for $n { const NAME: &'static str = $s; fn accepts(k: Kind) -> bool { matches!(k, $(Kind::$k)|+) } }
    )* } }
    kinds! {
        FileK = "file": File | RepoAt | Blob;
        NodeK = "node": Node;
        PersonK = "person": Person;
        AgentK = "agent": Agent;
        CellK = "cell": Cell | CellOp;
        CapK = "capability": Cap;
    }
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct Typed<K: RefKind> {
        pub r: Ref,
        k: PhantomData<K>,
    }
    impl<K: RefKind> Typed<K> {
        pub fn new(r: Ref) -> Result<Self, Error> {
            if K::accepts(r.kind()) {
                Ok(Typed { r, k: PhantomData })
            } else {
                Err(Error(format!("{} is not a {} ref", r, K::NAME)))
            }
        }
        pub fn parse(s: &str) -> Result<Self, Error> {
            Self::new(Ref::parse(s)?)
        }
        /// `Pinned<K>`: only a ref that names exactly one thing.
        pub fn pinned(self) -> Result<Pinned<K>, Error> {
            if self.r.is_pinned() {
                Ok(Pinned(self))
            } else {
                Err(Error(format!("{} is not pinned", self.r)))
            }
        }
    }
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct Pinned<K: RefKind>(pub Typed<K>);
    impl<K: RefKind> Pinned<K> {
        pub fn get(&self) -> &Ref {
            &self.0.r
        }
    }
}

#[macro_export]
macro_rules! ce_ref {
    ($k:ty, $s:literal) => {
        $crate::typed::Typed::<$k>::parse($s).expect(concat!("ce_ref!: ", $s))
    };
    ($s:literal) => {
        $crate::Ref::parse($s).expect(concat!("ce_ref!: ", $s))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forms_round_trip() {
        for s in [
            "ce-ref://repo/b47ae72900538d9d902251c935592073814514e0a5db7f31b4731a2fc046f331/run.py",
            "repo:huey-scripts/run.py@3f2a1c sha256:3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51",
            "ce-blob:sha256:3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51",
            "node:pi-01",
            "person:leif ed25519:884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b",
            "agent:planner",
            "cell:erp.orders@1#GetOrder",
            "cap:884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b",
            "doc:ce-ref/docs/GLOBAL-FILES@v1.2.3#refs",
        ] {
            assert_eq!(Ref::parse(s).unwrap().to_string(), s);
        }
    }
    #[test]
    fn bare_is_not_pinned() {
        let r = Ref::parse("run.py").unwrap();
        assert_eq!(r.kind(), Kind::Bare);
        assert!(!r.is_pinned());
        assert!(Ref::parse("repo:a/b@3f2a1c sha256:9b1e…").is_err());
    }
    #[test]
    fn typed_refuses_other_kind() {
        use typed::*;
        assert!(Typed::<FileK>::parse("node:pi-01").is_err());
        let f = ce_ref!(FileK, "ce-blob:sha256:3f9b0d4d3e88a9987a8670f2ab9ff7b912448d8ade2bd369395d06e48c6feb51");
        assert!(f.pinned().is_ok());
    }
}
