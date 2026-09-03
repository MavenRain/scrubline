(* M18: a span becomes [REDACTED:<detector>:<fp8>], the first 8 hex
   chars of SHA-256(salt || 0x00 || canonical value) via the sha2 pin.
   [scrubbed] is abstract: [record] is its only constructor, it runs
   the detector sweep unconditionally, and a post-scrub key collision
   is a Duplicate_key reject with no value at all (fail closed).
   [encode] is the one path to egress bytes: one Message frame. *)

(* True on the space and the dash, the separators a Pan or Ssn holds. *)
val is_separator : char -> bool

(* One spelling per value: separators dropped, Eth_address lowercased. *)
val canonical : Detect.detector -> string -> string

(* The 8 lowercase hex chars of SHA-256(salt || 0x00 || value). *)
val fp8 : salt:string -> string -> string

(* The token a raw span becomes under this salt. *)
val token : salt:string -> Detect.detector -> string -> string

(* The emit currency: the sweep ran and the keys were checked. *)
type scrubbed

(* The routing tag, carried verbatim and never scanned. *)
val tag : scrubbed -> string

(* The event time, carried verbatim and never scanned. *)
val time : scrubbed -> Forward.time

(* The scrubbed record fields. *)
val fields : scrubbed -> Forward.record

(* The only constructor: sweep, then the duplicate-key check. *)
val record :
  salt:string -> Forward.event -> (scrubbed * Detect.span list, Err.t) result

(* The one path to egress bytes: [tag, time, record], minimal headers. *)
val encode : scrubbed -> string
