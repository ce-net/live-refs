# live-refs

A live system: one kind of name, the ce-ref, connects anything to anything across a network of devices. A file on a
personal laptop, a blob, a repo file pinned at a commit, a node, a person, an agent key, a cell op, a capability and an
enterprise system wrapped as a cell are all named the same way, resolved to where they live now, and pinned to their
content hash so changed bytes are refused.

Page: https://ce-net.github.io/live-refs/

## Quickstart

```sh
git clone https://github.com/ce-net/live-refs
cd live-refs
cargo run -- sim            # four device processes on 127.0.0.1, eight steps, proof/run.jsonl
cargo run -- verify proof   # every step signed and chained, every answer signed by the device that gave it
cargo test --workspace      # the walk end to end, id byte-identity, contracts, the door, the proof log
```

Needs Rust (stable) on Linux or macOS. No network, keys, accounts or private crates: a fresh clone runs as is. The
first `cargo run` also builds `erp-legacy`, the ordinary order system that one of the devices wraps.

## What the run shows

Four devices, each its own process with its own ed25519 key and door: `laptop`, `server`, `enterprise`, `phone`. Every
call between them is signed by the caller, checked by the door against the caller's grant (a cap v3 chain written in
CAL and signed by the mesh root), and answered with the answering device's signature.

| Step | What happens | Proof (recorded run) |
|---|---|---|
| 1 | Nine refs, one per kind, each resolved to where it lives now | 9 of 9 resolved |
| 2 | `plan.md` moves from `laptop` to `server`; the id stays the same and every device follows | converged, same id |
| 3 | Pin it, change one byte, `ref.pin.Fetch` returns `Refused{want, got}` | refused |
| 4 | A CAL grant names `erp.orders.GetOrder` and a pinned report file; the executor on `enterprise` fetches the report from wherever it lives and CAL hashes it before the order system is asked | allowed; another op refused; tampered report refused |
| 5 | An `Asset` row on `server` points at an invoice on `phone`, read from `enterprise` | bytes match the row's pin |
| 6 | `ref.graph.Links` on the row: the row, the grant, the commit and the reader, each edge with its why | 12 edges |
| 7 | `phone` is cut off and resolves from its local index, marked with the time of its newest entry | 3 of 3 offline |
| 8 | `run.py` is refused as ambiguous (two different files); CAL refuses it too; the pinned form resolves | 1 refused, 1 accepted |

The numbers of the last recorded run are in [`proof/summary.json`](proof/summary.json); each call is a line of
[`proof/run.jsonl`](proof/run.jsonl).

## The ids

[`crates/ce-ref-id`](crates/ce-ref-id) is the Rust form of every ce-ref id, byte-identical to the reference
implementation:

| Kind | Form |
|---|---|
| file | `ce-ref://repo/<sha256 of the normalized git origin>/<path>` |
| repo path at a commit | `repo:<repo>/<path>@<commit> sha256:<hash>` |
| blob | `ce-blob:sha256:<hash>` |
| node | `node:<name>`, `node:<64 hex>` |
| person, agent key | `person:<id> ed25519:<64 hex>`, `agent:<lane> ed25519:<64 hex>` |
| cell, cell op | `cell:<api>@<major>`, `cell:<api>@<major>#<Op>` |
| capability | `cap:<64 hex link id>` |

`crates/ce-ref-id/vectors/ids.json` holds the reference implementation's answers for 60 inputs (origins with
credentials, odd hosts, unsafe paths, percent-encoding, malformed refs). The test checks the Rust against them, and runs
the reference implementation itself when a checkout of it is present. Typed refs (`Typed<FileK>`, `Pinned<FileK>`,
`ce_ref!`) refuse a ref of the wrong kind or an unpinned one where a pin is required.

## Layout

| Path | What |
|---|---|
| `contracts/*.rs` | The typed contracts of `ref.resolve@1`, `ref.pin@1`, `ref.graph@1`, `refs.catalog@1`, `erp.orders@1`, written once in `api!` form |
| `crates/wire-lite` | An open `api!` with the grammar and schema hash of `ce_wire::api!`, so the sim compiles the same contract files |
| `crates/refs-api` | The contracts compiled for the sim |
| `crates/sim-mesh` | Child-process nodes on loopback: signed calls, door, kill, partition, heal |
| `crates/live-proof` | Signed, hash-chained `Step` records and their verifier |
| `src/node.rs` | One device: its door, gate and cells |
| `src/sim.rs` | The eight steps |
| `src/bin/erp-legacy.rs` | The enterprise system: plain HTTP and JSON, knows nothing about the mesh |
| `cells/` | The same cells behind a real ce-net door (see below) |
| `docs/` | The page, replaying the recorded runs |

CAL and cap v3 come from [ce-net-proto](https://github.com/ce-net/ce-net-proto) (Apache-2.0).

## Real cells

`cells/` holds `ref.resolve`, `ref.pin` and `ref.graph` as cells for a node running the ce-net door, compiled from the
same contract files by `ce_wire::api!` (a test there checks the schema hashes equal the sim's), and `live-refs-live`,
which runs the walk against them through the door with the node's own capability. They are recorded on ops-1 in
[`proof/live.jsonl`](proof/live.jsonl): a repo file pinned at a commit and fetched, a changed file refused, a node, two
cells and a blob resolved, `README.md` refused as ambiguous across 1,000+ checkouts, and the graph read from the live
reference extractor. **`cells/` does not build from a fresh clone:** it depends on the ce-net door crates, which are not
public. The sim in the repo root does not use them.

## License

Apache-2.0.
