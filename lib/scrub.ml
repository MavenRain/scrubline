(* M18: the token function and the emit currency.  A resolved span
   becomes [REDACTED:<detector>:<fp8>], where <detector> is
   [Detect.to_string] and fp8 is the first 8 lowercase hex chars of
   SHA-256(salt || 0x00 || canonical value) through the sha2 pin.

   The canonical value is one spelling per value, so the same card
   gets the same token whatever its layout: a Pan or an Ssn span drops
   its separators (space and dash), an Eth_address span is lowercased
   whole (the 0x included), and an Aws_key or a Sol_pubkey span is
   kept as is.  The salt is opaque bytes;  an empty salt is accepted
   and means unsalted.  A salt that ends in NUL cannot be told from a
   value that starts with NUL under the 0x00 separator.  No detector
   span starts with NUL (every detector alphabet excludes it), so
   tokens stay unambiguous and the raw boundary is pinned as
   documented, not defended against.

   [scrubbed] is the emit currency and it is abstract (scrub.mli):
   [record] is its only constructor, and it runs [Detect.record] over
   the record unconditionally.  A value of this type therefore says
   the sweep ran and the keys were checked, so egress cannot name
   bytes that never went through here.  A clean record is still a
   [scrubbed] value with an empty span list.

   After the sweep, [record] checks every map level of the result for
   a key that now equals another key of the same map: the top-level
   field names as strings, and every nested [Msgpack.Map] under
   structural equality, the rule the decoder already applies in
   msgpack.ml.  Two distinct keys can meet on one token (a
   fingerprint-prefix collision, or a literal token already present as
   a key).  That is [Err.Malformed Gate_core.Duplicate_key] and no
   [scrubbed] value exists for the record: it fails closed rather than
   emitting a map the decoder would reject.  The check runs on every
   record, dirty or clean;  the clean case re-checks what the decoder
   already proved, which is the layered guard and cheap at record
   scale.

   The tag and the time ride verbatim and are never scanned: a tag is
   a routing label, not payload (held for the M19 corpus).

   [encode] is the one path to egress bytes: one Message frame
   [tag, time, record] with minimal headers, the time as an int for
   Seconds and as the EventTime fixext 8 for Event_time, so
   [Forward.decode] reads the bytes back as the same event with no
   options.

   Growth: a token is 23 bytes for pan and ssn, 27 for aws_key, 30 for
   sol_pubkey and 31 for eth_address.  The worst span is a bare
   9-digit SSN, so a record grows by at most 14 bytes per span. *)

(* The separators a Pan or Ssn window may hold between digit groups. *)
let is_separator (c : char) : bool = c = ' ' || c = '-'

(* What the fingerprint hashes: one spelling per value. *)
let canonical (d : Detect.detector) (raw : string) : string =
  match d with
  | Detect.Pan | Detect.Ssn ->
    String.of_seq
      (Seq.filter (fun (c : char) -> not (is_separator c)) (String.to_seq raw))
  | Detect.Eth_address -> String.lowercase_ascii raw
  | Detect.Aws_key | Detect.Sol_pubkey -> raw

(* The fingerprint width in hex chars. *)
let prefix_len : int = 8

(* The first [prefix_len] chars of a string;  total on any length. *)
let prefix_of (s : string) : string =
  String.of_seq
    (List.to_seq
       (List.filteri
          (fun (i : int) (_ : char) -> i < prefix_len)
          (List.of_seq (String.to_seq s))))

(* SHA-256(salt || 0x00 || value), the first 8 hex chars. *)
let fp8 ~(salt : string) (value : string) : string =
  prefix_of (Sha2.Sha256.hex (salt ^ "\x00" ^ value))

(* The token a span becomes. *)
let token ~(salt : string) (d : Detect.detector) (raw : string) : string =
  "[REDACTED:" ^ Detect.to_string d ^ ":" ^ fp8 ~salt (canonical d raw) ^ "]"

(* The emit currency.  Abstract in scrub.mli: [record] below is the only
   constructor, so a value of this type says the sweep ran and the keys
   were checked. *)
type scrubbed = { tag : string; time : Forward.time; record : Forward.record }

let tag (s : scrubbed) : string = s.tag

let time (s : scrubbed) : Forward.time = s.time

let fields (s : scrubbed) : Forward.record = s.record

(* Pairwise distinct under structural equality, the decoder's rule. *)
let distinct (ks : 'a list) : bool =
  let rec go (seen : 'a list) (rest : 'a list) : bool =
    match rest with
    | [] -> true
    | k :: tl -> (not (List.mem k seen)) && go (k :: seen) tl
  in
  go [] ks

(* Every Map at every depth has distinct keys. *)
let rec keys_distinct (v : Msgpack.t) : bool =
  match v with
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Str _ | Msgpack.Bin _ | Msgpack.Ext (_, _) ->
    true
  | Msgpack.Arr items -> List.for_all keys_distinct items
  | Msgpack.Map pairs ->
    distinct (List.map fst pairs)
    && List.for_all
         (fun ((_ : Msgpack.t), (v : Msgpack.t)) -> keys_distinct v)
         pairs

(* The top-level field names, then every nested map. *)
let record_keys_distinct (r : Forward.record) : bool =
  distinct (List.map fst r)
  && List.for_all
       (fun ((_ : string), (v : Msgpack.t)) -> keys_distinct v)
       r

(* The only constructor of [scrubbed].  The sweep runs whatever the
   record holds;  a post-scrub key collision is the typed reject and no
   value comes back for it. *)
let record ~(salt : string) (e : Forward.event) :
    (scrubbed * Detect.span list, Err.t) result =
  let fields, spans = Detect.record ~token:(token ~salt) e.Forward.record in
  match () with
  | () when record_keys_distinct fields ->
    Ok ({ tag = e.Forward.tag; time = e.Forward.time; record = fields }, spans)
  | () -> Error (Err.Malformed Gate_core.Duplicate_key)

(* The time slot of the Message frame: an int, or EventTime fixext 8
   (four big-endian bytes of seconds, four of nanoseconds), the layout
   forward.ml reads. *)
let time_value (t : Forward.time) : Msgpack.t =
  match t with
  | Forward.Seconds n -> Msgpack.Int n
  | Forward.Event_time { sec; nsec } ->
    Msgpack.Ext (0, Msgpack.be 4 sec ^ Msgpack.be 4 nsec)

(* The only path to egress bytes: one Message frame [tag, time, record]
   with minimal headers. *)
let encode (s : scrubbed) : string =
  Msgpack.encode
    (Msgpack.Arr
       [ Msgpack.Str s.tag;
         time_value s.time;
         Msgpack.Map
           (List.map
              (fun ((k : string), (v : Msgpack.t)) -> (Msgpack.Str k, v))
              s.record) ])
