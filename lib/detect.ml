(* M12: the span framework.  This module owns candidate hygiene,
   overlap resolution, replacement application, and the walk over a
   decoded tree.  A [matcher] is the plug-in point and [matchers] is
   the production list: it carries Pan since M13 and Ssn since M14,
   and M15..M17 add the rest.

   A span is a pair of byte offsets, half-open [start, stop), into the
   decoded UTF-8 string it was found in.  Offsets are per string, not
   global: the tree walk reports each span against the string it came
   from.

   The token function is a parameter.  M18 supplies the salted
   fingerprint form, the tests supply plain markers.  The framework is
   total whatever a matcher returns: ill-formed candidates are dropped
   and overlaps are resolved before any byte moves, so a careless
   matcher cannot make the replacement partial. *)

type detector =
  | Pan
  | Ssn
  | Aws_key
  | Sol_pubkey
  | Eth_address

type span = { detector : detector; start : int; stop : int }

(* One detector's candidate finder.  The framework stamps the
   detector, so a matcher returns bare (start, stop) pairs. *)
type matcher = { emits : detector; find : string -> (int * int) list }

(* The order of the DESIGN section 3 detectors table.  Lower wins. *)
let priority (d : detector) : int =
  match d with
  | Pan -> 0
  | Ssn -> 1
  | Aws_key -> 2
  | Sol_pubkey -> 3
  | Eth_address -> 4

(* The detector field of the M18 token, and the M23 metrics label. *)
let to_string (d : detector) : string =
  match d with
  | Pan -> "pan"
  | Ssn -> "ssn"
  | Aws_key -> "aws_key"
  | Sol_pubkey -> "sol_pubkey"
  | Eth_address -> "eth_address"

(* A candidate is usable only if it names bytes that exist.  An empty
   or inverted span, or one reaching outside [0, len], is dropped. *)
let well_formed ~(len : int) (s : span) : bool =
  0 <= s.start && s.start < s.stop && s.stop <= len

let span_length (s : span) : int = s.stop - s.start

(* Leftmost first, then longest, then the table order. *)
let compare_span (a : span) (b : span) : int =
  match () with
  | () when a.start <> b.start -> compare a.start b.start
  | () when span_length a <> span_length b ->
    compare (span_length b) (span_length a)
  | () -> compare (priority a.detector) (priority b.detector)

(* Drop the ill-formed, sort, then sweep greedily from edge 0.  The
   output is well formed, ascending, and pairwise disjoint; adjacent
   spans both survive.  It is a subset of the input, so identical
   duplicates collapse to one, and it is idempotent. *)
let resolve ~(len : int) (cands : span list) : span list =
  let kept, (_ : int) =
    List.filter (well_formed ~len) cands
    |> List.stable_sort compare_span
    |> List.fold_left
         (fun (kept, edge) (s : span) ->
           match () with
           | () when s.start >= edge -> (s :: kept, s.stop)
           | () -> (kept, edge))
         ([], 0)
  in
  List.rev kept

let scan_with (ms : matcher list) (s : string) : span list =
  List.concat_map
    (fun (m : matcher) ->
      List.map
        (fun ((a : int), (b : int)) ->
          { detector = m.emits; start = a; stop = b })
        (m.find s))
    ms
  |> resolve ~len:(String.length s)

(* Pan since M13, Ssn since M14.  M15..M17 each add one entry, in
   table order. *)
let matchers : matcher list =
  [ { emits = Pan; find = Pan.find }; { emits = Ssn; find = Ssn.find } ]

let scan (s : string) : span list = scan_with matchers s

let string_of_rev (acc : char list) : string =
  String.of_seq (List.to_seq (List.rev acc))

(* The replacement sweep carries either the gap bytes since the last
   token, or the bytes of the span it is inside.  Both lists are
   reversed, and so is [out]. *)
type mode =
  | Gap of char list
  | Inside of span * char list

type sweep = { pending : span list; mode : mode; out : string list }

(* Does the next pending span open at this byte?  A small sum type
   keeps the Gap arm flat and free of a match on an option. *)
type opening =
  | Opens of span * span list
  | Stays

let opening_at (i : int) (pending : span list) : opening =
  match pending with
  | [] -> Stays
  | sp :: rest -> (
    match () with
    | () when i = sp.start -> Opens (sp, rest)
    | () -> Stays)

(* One sweep over the bytes.  Gap bytes copy through byte exact.  A
   span's bytes are accumulated, never copied, and at its last byte
   the whole span becomes [token detector matched_bytes]. *)
let replace ~(token : detector -> string -> string) (s : string)
    (spans : span list) : string =
  let kept = resolve ~len:(String.length s) spans in
  let step (st : sweep) (((i : int), (c : char)) : int * char) : sweep =
    match st.mode with
    | Gap gap -> (
      match opening_at i st.pending with
      | Stays -> { st with mode = Gap (c :: gap) }
      | Opens (sp, rest) ->
        let out = string_of_rev gap :: st.out in
        (match () with
         | () when sp.stop = i + 1 ->
           { pending = rest;
             mode = Gap [];
             out = token sp.detector (String.make 1 c) :: out }
         | () -> { pending = rest; mode = Inside (sp, [ c ]); out }))
    | Inside (sp, acc) ->
      let acc = c :: acc in
      (match () with
       | () when i + 1 = sp.stop ->
         { st with
           mode = Gap [];
           out = token sp.detector (string_of_rev acc) :: st.out }
       | () -> { st with mode = Inside (sp, acc) })
  in
  let final =
    Seq.fold_left step
      { pending = kept; mode = Gap []; out = [] }
      (String.to_seqi s)
  in
  let out =
    match final.mode with
    | Gap gap -> string_of_rev gap :: final.out
    (* A well-formed span closes at stop - 1, which is at most the
       last index, so this arm is unreachable after [resolve].  It
       still fails closed: the open span emits its token, and the raw
       bytes it holds are dropped rather than copied out. *)
    | Inside (sp, acc) -> token sp.detector (string_of_rev acc) :: final.out
  in
  String.concat "" (List.rev out)

(* Str values and Str keys alike are scanned.  Bin and Ext payloads
   are opaque bytes and are never scanned as text (forward.ml, DESIGN
   section 5).  Spans come back in tree order: array items in order,
   map pairs in order, key before value. *)
let rec tree_with (ms : matcher list)
    ~(token : detector -> string -> string) (v : Msgpack.t) :
    Msgpack.t * span list =
  match v with
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Bin _ | Msgpack.Ext (_, _) -> (v, [])
  | Msgpack.Str s ->
    let spans = scan_with ms s in
    (Msgpack.Str (replace ~token s spans), spans)
  | Msgpack.Arr items ->
    let items, spans =
      List.fold_left
        (fun (items, spans) item ->
          let item, got = tree_with ms ~token item in
          (item :: items, List.rev_append got spans))
        ([], []) items
    in
    (Msgpack.Arr (List.rev items), List.rev spans)
  | Msgpack.Map pairs ->
    let pairs, spans =
      List.fold_left
        (fun (pairs, spans) ((k : Msgpack.t), (w : Msgpack.t)) ->
          let k, ks = tree_with ms ~token k in
          let w, vs = tree_with ms ~token w in
          ((k, w) :: pairs, List.rev_append vs (List.rev_append ks spans)))
        ([], []) pairs
    in
    (Msgpack.Map (List.rev pairs), List.rev spans)

let tree ~(token : detector -> string -> string) (v : Msgpack.t) :
    Msgpack.t * span list =
  tree_with matchers ~token v

(* A top-level field name is a plain string, so it is scanned
   directly; the value goes through the tree walk.  Spans come back in
   field order, key before value. *)
let record_with (ms : matcher list) ~(token : detector -> string -> string)
    (r : Forward.record) : Forward.record * span list =
  let fields, spans =
    List.fold_left
      (fun (fields, spans) ((k : string), (v : Msgpack.t)) ->
        let ks = scan_with ms k in
        let k = replace ~token k ks in
        let v, vs = tree_with ms ~token v in
        ((k, v) :: fields, List.rev_append vs (List.rev_append ks spans)))
      ([], []) r
  in
  (List.rev fields, List.rev spans)

let record ~(token : detector -> string -> string) (r : Forward.record) :
    Forward.record * span list =
  record_with matchers ~token r
