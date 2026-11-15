//! A mesh of real processes on 127.0.0.1. Each node has its own ed25519 key and one listening port (its door).
//! A call is one JSON line: `{from, api, op, body, ts, nonce, sig}`, signed by the caller's key over
//! `sha256(api \n op \n body \n ts \n nonce)`. The door checks the signature against the roster before any cell
//! sees the call, and the answer is signed by the node that answered. A partitioned node refuses every call from a
//! peer it is cut off from and cannot reach them either; only the run's root key may drive it (kill, partition, heal).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

pub fn key_hex(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

/// A fresh key from the OS.
pub fn new_key() -> SigningKey {
    let mut seed = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").expect("/dev/urandom");
    std::io::Read::read_exact(&mut f, &mut seed).unwrap();
    SigningKey::from_bytes(&seed)
}

pub fn key_from_hex(h: &str) -> SigningKey {
    SigningKey::from_bytes(&hex::decode(h.trim()).unwrap().try_into().unwrap())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub port: u16,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Roster {
    pub root: String,
    pub nodes: BTreeMap<String, Member>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub from: String,
    pub api: String,
    pub op: String,
    pub body: Value,
    pub ts: u64,
    pub nonce: u64,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    pub body: Value,
    /// Why the door or the cell refused, verbatim.
    pub refused: Option<String>,
    pub node: String,
    pub sig: String,
}

fn digest(api: &str, op: &str, body: &str, ts: u64, nonce: u64) -> Vec<u8> {
    Sha256::digest(format!("{api}\n{op}\n{body}\n{ts}\n{nonce}")).to_vec()
}

fn vk(h: &str) -> Result<VerifyingKey, String> {
    let b: [u8; 32] = hex::decode(h).map_err(|e| e.to_string())?.try_into().map_err(|_| "key length".to_string())?;
    VerifyingKey::from_bytes(&b).map_err(|e| e.to_string())
}

fn sig_ok(key: &str, msg: &[u8], sig: &str) -> bool {
    let Ok(k) = vk(key) else { return false };
    let Ok(s) = hex::decode(sig) else { return false };
    let Ok(s): Result<[u8; 64], _> = s.try_into() else { return false };
    k.verify(msg, &Signature::from_bytes(&s)).is_ok()
}

impl Reply {
    pub fn ok(body: Value) -> Reply {
        Reply { ok: true, body, refused: None, node: String::new(), sig: String::new() }
    }
    pub fn refused(why: impl Into<String>) -> Reply {
        Reply { ok: false, body: Value::Null, refused: Some(why.into()), node: String::new(), sig: String::new() }
    }
    fn signed_bytes(&self) -> Vec<u8> {
        Sha256::digest(format!("{}\n{}\n{:?}", self.node, self.body, self.refused)).to_vec()
    }
    /// The answering node's signature over the answer.
    pub fn verify(&self, roster: &Roster) -> bool {
        roster.nodes.get(&self.node).is_some_and(|m| sig_ok(&m.key, &self.signed_bytes(), &self.sig))
    }
}

/// Who this process is: its name, key and the run's roster, plus who it is cut off from.
pub struct Mesh {
    pub name: String,
    pub key: SigningKey,
    pub roster: Roster,
    pub cut: Mutex<BTreeSet<String>>,
}

pub const CTL: &str = "sim.ctl";

impl Mesh {
    pub fn new(name: &str, key: SigningKey, roster: Roster) -> Arc<Mesh> {
        Arc::new(Mesh { name: name.into(), key, roster, cut: Mutex::new(BTreeSet::new()) })
    }

    pub fn is_cut(&self, peer: &str) -> bool {
        let c = self.cut.lock().unwrap();
        c.contains("*") && peer != self.name || c.contains(peer)
    }

    /// A signed call to `to`. `Err` is a transport failure (unreachable, partitioned, bad answer signature).
    pub fn call(&self, to: &str, api: &str, op: &str, body: Value, timeout: Duration) -> Result<Reply, String> {
        if api != CTL && self.is_cut(to) {
            return Err(format!("{}: cut off from {to} (partitioned)", self.name));
        }
        let m = self.roster.nodes.get(to).ok_or(format!("{to}: not in the roster"))?;
        let ts = now_ms();
        let nonce = u64::from_le_bytes(Sha256::digest(format!("{ts}{}{}", self.name, rand_u64()))[..8].try_into().unwrap());
        let b = body.to_string();
        let sig = hex::encode(self.key.sign(&digest(api, op, &b, ts, nonce)).to_bytes());
        let f = Frame { from: self.name.clone(), api: api.into(), op: op.into(), body, ts, nonce, sig };
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], m.port));
        let mut s = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("{to}: unreachable: {e}"))?;
        s.set_read_timeout(Some(timeout)).ok();
        s.set_nodelay(true).ok();
        let mut line = serde_json::to_string(&f).unwrap();
        line.push('\n');
        s.write_all(line.as_bytes()).map_err(|e| format!("{to}: {e}"))?;
        let mut r = BufReader::new(s);
        let mut out = String::new();
        r.read_line(&mut out).map_err(|e| format!("{to}: no answer: {e}"))?;
        if out.is_empty() {
            return Err(format!("{to}: closed without an answer"));
        }
        let rep: Reply = serde_json::from_str(&out).map_err(|e| format!("{to}: bad answer: {e}"))?;
        if !rep.verify(&self.roster) || rep.node != to {
            return Err(format!("{to}: the answer is not signed by {to}"));
        }
        Ok(rep)
    }

    /// Serves the door: checks each frame's signature (a ctl frame must be signed by the root), the partition, then
    /// hands it to `handle`. One thread per connection.
    pub fn serve<H>(self: &Arc<Self>, handle: H) -> !
    where
        H: Fn(&Frame) -> Reply + Send + Sync + 'static,
    {
        let port = self.roster.nodes[&self.name].port;
        let l = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|e| panic!("{}: bind {port}: {e}", self.name));
        let h = Arc::new(handle);
        for c in l.incoming().flatten() {
            let (me, h) = (self.clone(), h.clone());
            std::thread::spawn(move || {
                let _ = me.one(c, &*h);
            });
        }
        unreachable!()
    }

    fn one<H: Fn(&Frame) -> Reply>(&self, c: TcpStream, h: &H) -> std::io::Result<()> {
        c.set_nodelay(true).ok();
        let mut w = c.try_clone()?;
        let mut r = BufReader::new(c);
        let mut line = String::new();
        r.read_line(&mut line)?;
        let mut rep = match serde_json::from_str::<Frame>(&line) {
            Err(e) => Reply::refused(format!("door: not a frame: {e}")),
            Ok(f) => {
                let key = if f.api == CTL { Some(self.roster.root.clone()) } else { self.roster.nodes.get(&f.from).map(|m| m.key.clone()) };
                let d = digest(&f.api, &f.op, &f.body.to_string(), f.ts, f.nonce);
                match key {
                    None => Reply::refused(format!("door: {} is not a member of this mesh", f.from)),
                    Some(k) if !sig_ok(&k, &d, &f.sig) => Reply::refused(format!("door: bad signature from {}", f.from)),
                    Some(_) if f.api != CTL && self.is_cut(&f.from) => Reply::refused(format!("door: {} is cut off from {} (partitioned)", self.name, f.from)),
                    Some(_) => h(&f),
                }
            }
        };
        rep.node = self.name.clone();
        rep.sig = hex::encode(self.key.sign(&rep.signed_bytes()).to_bytes());
        let mut out = serde_json::to_string(&rep).unwrap();
        out.push('\n');
        w.write_all(out.as_bytes())
    }
}

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut b);
    }
    u64::from_le_bytes(b)
}

/// The controller side: starts node processes and drives them.
pub struct Controller {
    pub mesh: Arc<Mesh>,
    pub children: Mutex<BTreeMap<String, std::process::Child>>,
    pub spawn: Box<dyn Fn(&str) -> std::process::Child + Send + Sync>,
}

impl Controller {
    pub fn start(&self, name: &str) {
        let c = (self.spawn)(name);
        self.children.lock().unwrap().insert(name.into(), c);
    }
    pub fn wait_up(&self, name: &str, within: Duration) -> Result<Duration, String> {
        let t = Instant::now();
        while t.elapsed() < within {
            if self.mesh.call(name, CTL, "Ping", Value::Null, Duration::from_millis(200)).is_ok() {
                return Ok(t.elapsed());
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        Err(format!("{name} did not come up in {within:?}"))
    }
    pub fn kill(&self, name: &str) {
        if let Some(mut c) = self.children.lock().unwrap().remove(name) {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    pub fn ctl(&self, name: &str, op: &str, body: Value) -> Result<Reply, String> {
        self.mesh.call(name, CTL, op, body, Duration::from_secs(10))
    }
    pub fn stop_all(&self) {
        let names: Vec<String> = self.children.lock().unwrap().keys().cloned().collect();
        for n in names {
            self.kill(&n);
        }
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.stop_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn door_refuses_strangers_and_partitions() {
        let (a, b, root) = (new_key(), new_key(), new_key());
        let port = 40000 + (rand_u64() % 20000) as u16;
        let mut r = Roster { root: key_hex(&root), nodes: BTreeMap::new() };
        r.nodes.insert("a".into(), Member { port, key: key_hex(&a) });
        r.nodes.insert("b".into(), Member { port: port + 1, key: key_hex(&b) });
        let srv = Mesh::new("a", a, r.clone());
        let s2 = srv.clone();
        std::thread::spawn(move || s2.serve(|f| Reply::ok(serde_json::json!({"echo": f.op}))));
        std::thread::sleep(Duration::from_millis(100));
        let cli = Mesh::new("b", b, r.clone());
        let rep = cli.call("a", "x", "Op", Value::Null, Duration::from_secs(2)).unwrap();
        assert!(rep.ok && rep.verify(&r));
        let stranger = Mesh::new("b", new_key(), r.clone());
        let rep = stranger.call("a", "x", "Op", Value::Null, Duration::from_secs(2)).unwrap();
        assert!(rep.refused.unwrap().contains("bad signature"));
        srv.cut.lock().unwrap().insert("b".into());
        let rep = cli.call("a", "x", "Op", Value::Null, Duration::from_secs(2)).unwrap();
        assert!(rep.refused.unwrap().contains("partitioned"));
    }
}
