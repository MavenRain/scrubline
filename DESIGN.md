# scrubline: design

A redaction gate for the EKS-to-Elasticsearch log pipeline that cannot crash
and cannot leak a detected field. Scrubline sits between the log agents and
the index. It speaks the Fluent Bit forward protocol on both sides. Every
parse path is a compile-checked case:

- An arriving record is one of four typed classes: well-formed, malformed,
  oversized, invalid UTF-8. The classifier is a total function over bytes.
  There is no fifth outcome and no exception path.
- A well-formed record is scanned and scrubbed before it can reach the emit
  constructor. The scrubbed record is a distinct type, and the egress encoder
  accepts only that type, so an unscrubbed record cannot serialize toward
  the index.
- The other three classes route to a dead-letter stream with a typed reason.
  Bad input cannot crash the gate, and it cannot pass through the gate.
- The library raises nothing: no `raise`, no `failwith`, no `assert`, no
  partial indexing, every `Unix` call wrapped once at the boundary. The fuzz
  gate holds that closed over structural and mutational input.

Why this shape. C log agents carry a known CVE class around malformed input
(CVE-2024-4323 in Fluent Bit is the recent instance), and regex filters
under-redact silently: separators, line wraps, and invalid UTF-8 each slip a
PAN past a byte-level pattern. Scrubline scans decoded values, not raw
bytes, and validates candidates semantically (Luhn for PAN, a length-32
base58 decode for Solana keys). The pipeline is multi-tenant and, since
stablecoin launch, carries wallet addresses and transaction hashes next to
PAN and SSN fields, so the detector set covers both families.

## 1. Dependencies

Stdlib-only core (plus `unix` for `io/`), and two of our own pinned
libraries (karamel-710 switch):

- `ctlk_topos` (git+file pin): the CTLK-in-topos model-checker kernel, for
  the `model/` layer.
- `sha2` (git+file pin): SHA-256 for redaction fingerprints, SHA-512 for the
  forward-protocol shared-key handshake digest.

No msgpack dependency, no regex engine, no web framework. The codecs and
detectors are part of the audited surface, so they are written here, total,
against the caps in one module.

## 2. Threat model: the failure classes this design deletes

| Class | Instance | Where it dies here |
|---|---|---|
| Malformed input crashes the agent | CVE-2024-4323 (Fluent Bit), msgpack C-parser class | total decoder over a bounded cursor; `Malformed` is a typed class routed to the dead-letter stream |
| Regex under-redaction | separator and line-wrap PAN forms | detectors run on decoded UTF-8 values with semantic checks (Luhn, base58 decode), not on raw bytes |
| Invalid UTF-8 smuggling | bytes a byte-regex reads differently than the indexer | `Bad_utf8` is a typed class; such records dead-letter and never reach the index |
| Oversized frame as allocation bomb | crafted length headers | caps checked before allocation; `Oversized` is a typed class |
| Compressed payload bypass | CompressedPackedForward | typed reject to the dead-letter stream (no gzip decode in V1, documented) |
| Silent drop | filter crash-restart loses chunks | conservation: every ingested record terminates as exactly one of Emit or Dead_letter; the model proves it, the fuzz gate counts it |
| Duplicate map keys | dedup divergence between filter and indexer | duplicate keys in any decoded map are a typed reject |
| Secret in a field name | naive filters scan values only | detectors walk keys and values of the whole decoded tree |
| Leak through the DLQ | DLQ carries the raw record | the DLQ is a separate forward tag routed to a quarantine index, never the main index; the operator boundary is documented |
| Ack loss | at-least-once delivery | a chunk ack goes upstream only after the downstream write |

## 3. Pipeline and API shape (lib/)

```
agents --forward/tcp--> scrubline --forward/tcp--> downstream --> index
                            |
                            +--forward/tcp--> dlq.<tag> (quarantine)
                            +--http--> GET /metrics (Prometheus)
```

```ocaml
module Caps : sig
  val frame_max : int      (* 4 MiB  *)
  val record_max : int     (* 1 MiB  *)
  val tag_max : int        (* 1024   *)
  val depth_max : int      (* 32     *)
  val entries_max : int    (* 8192 events per forward frame *)
  val string_max : int     (* 256 KiB per decoded string    *)
end

module Utf8 : sig
  val validate : string -> (unit, Gate_core.utf8_error) result
end

module Msgpack : sig
  type t =
    | Nil | Bool of bool | Int of int | Uint64_edge of string
    | Float of float | Str of string | Bin of string
    | Arr of t list | Map of (t * t) list
    | Ext of int * string
  type error
  val decode : string -> (t, error) result          (* total, caps enforced *)
  val encode : t -> string
end

module Forward : sig
  type time = Seconds of int | Event_time of { sec : int; nsec : int }
  type event = { tag : string; time : time; record : (string * Msgpack.t) list }
  type frame =
    | Message of event
    | Forward of { tag : string; entries : (time * (string * Msgpack.t) list) list }
    | Packed_forward of { tag : string; entries_bytes : string }
  val decode : string -> (frame * ack_option, Gate_core.input_class) result
end

module Detect : sig
  type detector = Pan | Ssn | Aws_key | Sol_pubkey | Eth_address
  type span = { detector : detector; start : int; stop : int }
  val scan : string -> span list        (* leftmost, longest, priority order *)
end

module Scrub : sig
  type scrubbed                          (* abstract; the only emit currency *)
  val record : salt:string -> Forward.event -> scrubbed * Detect.span list
  val encode : scrubbed -> string        (* the ONLY path to egress bytes *)
end

module Gate_core : sig                   (* shared with model/ via copy_files *)
  type input_class =
    | Valid of { dirty : bool }
    | Malformed of malformed_reason
    | Oversized of cap_violation
    | Bad_utf8 of utf8_error
  type outcome = Emit of { scrubbed : bool } | Dead_letter of dead_reason
  val route : input_class -> outcome     (* total; the one routing semantics *)
  val step : world -> world              (* record lifecycle, model-checked *)
end

module Metrics : sig
  type t                                 (* pure counter registry *)
  val render : t -> string               (* Prometheus text exposition 0.0.4 *)
end
```

`Scrub.scrubbed` is the leak gate at the type level: `Scrub.record` is its
only constructor, and it runs the detector sweep unconditionally. `io/`
egress takes `scrubbed` values only. A clean record is still a `scrubbed`
value (with an empty span list), so the type says "the sweep ran", not "the
record was dirty".

### Detectors

| Detector | Rule | False-positive controls |
|---|---|---|
| `Pan` | digit run of 13..19 digits, single space or dash separators allowed between groups, Luhn-valid, no digit adjacent to either end | Luhn-failing runs stay; runs embedded in longer digit runs stay |
| `Ssn` | `ddd-dd-dddd`, and bare 9-digit runs; area not 000, 666, 900..999; group not 00; serial not 0000 | invalid area/group/serial forms stay; digit-adjacent runs stay |
| `Aws_key` | `AKIA` or `ASIA` plus 16 chars of `[A-Z0-9]`, no `[A-Z0-9]` adjacent | prefix without the 16-char tail stays |
| `Sol_pubkey` | base58 run of 32..44 chars whose decode is exactly 32 bytes | base58 runs decoding to any other length stay |
| `Eth_address` | `0x` plus 40 hex chars, no alphanumeric adjacent | shorter or longer hex runs stay; EIP-55 case is not required (over-redaction is the safe side) |

Overlaps resolve leftmost first, then longest, then the priority order of
the table. The replacement token is `[REDACTED:<detector>:<fp8>]` where
`fp8` is the first 8 hex chars of `SHA-256(salt || 0x00 || canonical value)`
via the `sha2` pin. The canonical value strips separators for PAN and SSN
and lowercases hex for Ethereum. The same value under the same salt gets the
same token, so operators can correlate a card across log lines without
seeing it. An empty salt is accepted and documented as unsalted.

## 4. Model-driven method

Same method as tinysvid / x402-caml / jose-caml / tf-audit: `model/` holds a
CTLK model over the `ctlk_topos` kernel, and the record-lifecycle semantics
is one shared OCaml file (`lib/gate_core.ml`, copy_files into the model
library), so the model checks the same routing code the daemon runs.

A world is one record's journey: the arriving input class (chosen by the
adversary at the source fan-out) and the lifecycle stage (ingested,
classified, scanned, emitted with a scrub bit, dead-lettered with a reason,
crashed). Hazard states (emitted-unscrubbed-dirty, crashed) are
representable in the shared type, so their unreachability is a checked
property of the semantics, not an artifact of the encoding.

Two frames:

- The **Gate** frame steps with `Gate_core.step`. This is the shipped
  semantics.
- The **Filter** frame is the negative control: a byte-regex filter in a
  crashy C agent. Its step can miss a dirty record (emit unscrubbed), and
  malformed input can crash it or pass through it. The hazards must be
  reachable here, or the positive specs above are vacuous.

Agents and views: `Downstream` sees only "a record was emitted" (never the
gate internals, never the DLQ). `Operator` sees the metrics surface: the
terminal stage and the dead-letter reason tag.

Checked properties (`test/test_model.ml`, exit code is the gate):

| id | property | frame | expectation |
|----|----------|-------|-------------|
| S1 | AG (emitted -> safe) : no live sensitive value leaves the gate | Gate | valid |
| S2 | AG not crashed | Gate | valid |
| S3 | AG (malformed -> AG not emitted) | Gate | valid |
| S4 | AG (record -> AF (emitted or dead-lettered)) : no silent drop | Gate | valid |
| S5 | AG (dirty and emitted -> scrubbed) | Gate | valid |
| S6 | AG (emitted -> K_downstream safe) : downstream needs no scanner | Gate | valid |
| S7 | AG (dead(g) -> K_operator dead(g)) per reason group g | Gate | valid |
| S8 | EF (input = i and terminal(route i)) for every input i : each parse path reaches exactly the terminal `route` prescribes | Gate | valid |
| S9 | AG EX true : no deadlock | Gate | valid |
| S10 | AG (clean and emitted -> unscrubbed) : the gate does not mangle clean logs | Gate | valid |
| NG1 | AG not dirty | Gate | false |
| NG2 | EX emitted at init | Gate | false |
| NG3 | AG (emitted -> K_operator dirty) : metrics cannot see payload | Gate | false |
| NG4 | EF (dirty and emitted-unscrubbed) | Gate | false |
| F1 | EF (dirty and emitted-unscrubbed) : under-redaction reachable | Filter | true |
| F2 | EF crashed : the CVE class | Filter | true |
| F3 | EF (emitted and not K_downstream safe) | Filter | true |

Expected-false specs print a witness (`Witness.explain`: shortest E-path,
successor dump, or confusion pair). A checker that passes a negative
control is broken, and the runner treats that as a suite failure.

`test/test_correspondence.ml` pins the model to the code: an independent
hand-written mirror of the routing table, the `step` orbit against `route`
for every input, and a totality sweep of `step` over the full stage-input
cube (terminals are fixpoints, nothing is unhandled).

From model to types. Phase B's classifiers map decode errors onto the same
`input_class` constructors the model steps over, and Phase C's
`Scrub.scrubbed` makes S1 a compile-time fact for the daemon: egress cannot
name an unscrubbed record.

## 5. Strictness profile

- msgpack: full decode of what forward needs; duplicate map keys rejected;
  depth <= 32; counts and string sizes capped (section 3); a u64 above
  OCaml's int range is carried opaquely as `Uint64_edge` and never
  arithmetic; an i64 in [2^62, 2^63) is byte-identical to its unsigned
  view and rides `Uint64_edge` too; an i64 below -2^62 is a typed
  reject rather than a rounding; str, bin, and ext payloads share
  `string_max`; array and map counts share `entries_max`; float
  payloads decoded bit-exact.
- UTF-8: RFC 3629. Overlong forms, surrogates, out-of-range scalars, and
  truncated sequences are each a distinct typed error. Keys and string
  values must validate; `Bin` payloads are exempt and never scanned as text
  (documented).
- forward: Message, Forward, PackedForward accepted; CompressedPackedForward
  and unknown shapes are typed rejects; EventTime ext type 0 (8 bytes)
  and integer seconds accepted; the option map is parsed for `chunk` only.
- Caps are constants in `Caps`, checked before allocation, one module.
- Handshake: HELO/PING/PONG with shared_key_hexdigest per the forward spec,
  SHA-512 via the `sha2` pin; nonce and salt are opaque bytes; a digest
  mismatch closes the connection with a typed error.
- Time: seconds since epoch as int; EventTime nsec bounded to [0, 10^9).

## 6. Milestones

Phase A: model first.

| M | What | Status |
|---|------|--------|
| M1 | scaffold: dune-project, opam, licenses, gates.sh, DESIGN.md | DONE |
| M2 | model frame: record lifecycle over `ctlk_topos`, Gate + Filter frames, source fan-out, terminal self-loops, reachability | DONE |
| M3 | spec suite S1..S10 + NG1..NG4 + F1..F3, witnesses on expected-false, exit-code gate | DONE |
| M4 | `lib/gate_core.ml` shared semantics (copy_files into model), correspondence: independent routing mirror + step orbit vs route + totality sweep over the full cube | DONE |

Phase B: typed decode.

| M | What | Status |
|---|------|--------|
| M5 | `caps.ml`, `err.ml`, `reader.ml` total cursor (byte/take/u16be..u64be, no partial indexing) | DONE |
| M6 | `utf8.ml` total validator + corpus (overlong, surrogate, out-of-range, truncation) | DONE |
| M7 | msgpack scalar decode (nil, bool, int families with 64-bit edges, float, str/bin headers) + tests | DONE |
| M8 | msgpack containers: array/map/ext + EventTime, depth and count caps, duplicate-key reject + tests | DONE |
| M9 | msgpack encode for egress + roundtrip tests | TODO |
| M10 | `forward.ml`: Message / Forward / PackedForward to typed events; CompressedPackedForward and unknown shapes to typed rejects; fixture bytes from a real fluent-bit capture | TODO |
| M11 | ack: option-map chunk parse + ack response encode + tests | TODO |

Phase C: detectors.

| M | What | Status |
|---|------|--------|
| M12 | `detect.ml` span framework: scan keys and values of the decoded tree, overlap resolution (leftmost, longest, priority), replacement application; property: no span byte survives | TODO |
| M13 | `luhn.ml` + PAN detector + corpus (separator forms, Luhn-failing controls, embedded-run controls) | TODO |
| M14 | SSN detector (area/group/serial rules) + corpus | TODO |
| M15 | AWS access-key-id detector + corpus | TODO |
| M16 | `base58.ml` total decoder + Solana pubkey detector (decode length exactly 32) + corpus | TODO |
| M17 | Ethereum address detector + corpus | TODO |
| M18 | `scrub.ml`: salted SHA-256 fingerprint tokens via the `sha2` pin, `scrubbed` abstract type as the only emit currency, determinism tests | TODO |
| M19 | fixture corpus gate: per-detector fire and no-fire fixtures with expected scrubbed output, corpus table in `test/corpus/` | TODO |

Phase D: daemon.

| M | What | Status |
|---|------|--------|
| M20 | `io/tcp.ml`: listener + accept loop, every Unix call boundary-wrapped to typed errors, read cutoff at the frame cap | TODO |
| M21 | `lib/session.ml`: incremental feed (bytes to frames to events to `Gate_core.route`), `Incomplete {need; have}`, per-connection typed state, DLQ envelope (reason + original bytes as msgpack bin); one-byte-at-a-time test | TODO |
| M22 | `io/egress.ml`: downstream forward client, tag-preserving emit + `dlq.<tag>` emit, bounded reconnect backoff; ack upstream only after the downstream write | TODO |
| M23 | `metrics.ml`: pure counter registry (`records_total{result}`, `detections_total{detector}`, `dlq_total{reason}`, `bytes_in_total`, `connections_total`) + Prometheus text exposition + tests | TODO |
| M24 | `io/http_metrics.ml`: GET /metrics, minimal HTTP/1.1 responder + tests | TODO |
| M25 | `config.ml` + `bin/scrublined.ml` wiring (flags + env), socketpair smoke test | TODO |

Phase E: hardening.

| M | What | Status |
|---|------|--------|
| M26 | negative corpus: truncation sweep at every cut point of every fixture (with boundary positive controls), invalid-UTF-8 sweep, oversize matrix, each pinned to an exact error constructor | TODO |
| M27 | fuzz gate: seeded stdlib fuzzer (SplitMix64, structural + mutational), 50k cases through the full session step; asserts no escaping exception, outcome totality, and ingest = emit + dlq conservation; writes FUZZ.md; optional crowbar target when the switch has crowbar | TODO |
| M28 | handshake: HELO/PING/PONG shared-key auth (SHA-512 via the `sha2` pin), nonce/salt rules, digest checks + tests | TODO |

Phase F: ship.

| M | What | Status |
|---|------|--------|
| M29 | docker-compose demo: fluent-bit in, scrubline, fluent-bit out, OpenSearch; `demo.sh` drives the fixture corpus end to end and asserts the main index holds tokens and no PAN, the quarantine index holds the DLQ; DEMO.md | TODO |
| M30 | README + pitch, final gate sweep, LOC/size table | TODO |

## 7. Gates

`./gates.sh`: dune build (0 warnings) + model spec suite + correspondence +
every test suite + fixture corpus + fuzz gate. Each milestone lands
BUILT+GATED+MUTATION-CONFIRMED (behavioral mutants; KILLED(compile) is
vacuous) before review. Nothing is committed by the assistant.
