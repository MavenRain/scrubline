(* M10: Fluent Forward frames to typed events.  One complete frame's
   bytes (framing itself is M21's session) decode into the three
   accepted modes -- Message, Forward, PackedForward -- and
   CompressedPackedForward and every unknown shape are typed rejects.

   Ground truth is a real fluent-bit 5.1.1 capture (test_forward.ml):
   with the default config the entry time slot arrives as
   [EventTime, metadata-map] (the fluent-bit v2 event format), with
   time_as_integer it is a bare integer, and the ack-mode option map
   arrives under a non-minimal map32 header.  The decoder accepts the
   wrapped time slot only with an EMPTY metadata map: this gate must
   never drop bytes silently (S4's spirit), and metadata egress is
   undefined until M22 defines it, so a non-empty map is a typed
   reject routed to quarantine, not a silent strip.

   Shape discrimination follows the forward spec: the second element
   of the top-level array picks the mode (array = Forward, str/bin =
   PackedForward, integer/ext = Message), so a Message time slot is
   never the wrapped form -- the wrapper exists only inside entries.

   Caps at this layer: tag length (Tag_over), canonical record size
   (Record_over: the canonical re-encoding is what egress emits and
   what memory holds; the wire form is already inside frame_max at
   ingress), and packed entry count (Record_over, the vocabulary
   Count_over maps to in Err).  Times: integer seconds >= 0, or
   EventTime ext type 0 with exactly 8 bytes and nsec in [0, 10^9);
   an Uint64_edge time is a reject, not a rounding, like the i64
   edge in msgpack.ml.  Every Str in the record tree (keys and
   values alike) must be valid UTF-8; Bin and Ext payloads are
   opaque bytes and exempt (DESIGN section 5). *)

type time =
  | Seconds of int
  | Event_time of { sec : int; nsec : int }

type record = (string * Msgpack.t) list

type event = { tag : string; time : time; record : record }

type frame =
  | Message of event
  | Forward of { tag : string; entries : (time * record) list }
  | Packed_forward of { tag : string; entries_bytes : string }

(* The raw option map (chunk, size, compressed, fluent_signal, ...),
   carried untouched for M11's ack parse; [] when the frame has no
   options element. *)
type options = (Msgpack.t * Msgpack.t) list

let bad_shape : Err.t = Err.Malformed Gate_core.Bad_frame_shape

(* Every Str anywhere in the tree must be valid UTF-8; Bin and Ext
   payloads are opaque and exempt, and never scanned as text. *)
let rec validate_tree (v : Msgpack.t) : (unit, Err.t) result =
  match v with
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Bin _ | Msgpack.Ext (_, _) -> Ok ()
  | Msgpack.Str s ->
    Utf8.validate s |> Result.map_error (fun (u : Gate_core.utf8_error) -> Err.Bad_utf8 u)
  | Msgpack.Arr items ->
    List.fold_left
      (fun acc item -> Result.bind acc (fun () -> validate_tree item))
      (Ok ()) items
  | Msgpack.Map pairs ->
    List.fold_left
      (fun acc (k, w) ->
        Result.bind acc (fun () ->
          Result.bind (validate_tree k) (fun () -> validate_tree w)))
      (Ok ()) pairs

(* A top-level record field: the key must be a valid-UTF-8 Str (it
   becomes the typed field name); the value tree is UTF-8-checked. *)
let field_of (k : Msgpack.t) (v : Msgpack.t) : (string * Msgpack.t, Err.t) result =
  match k with
  | Msgpack.Str s ->
    Result.bind
      (Utf8.validate s
       |> Result.map_error (fun (u : Gate_core.utf8_error) -> Err.Bad_utf8 u))
      (fun () -> Result.map (fun () -> (s, v)) (validate_tree v))
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Bin _ | Msgpack.Arr _ | Msgpack.Map _
  | Msgpack.Ext (_, _) -> Error bad_shape

(* A record is a map with Str keys.  The canonical re-encoding is the
   record-size cap: canonical size <= wire size (minimal headers), and
   canonical bytes are what egress emits and what the process holds. *)
let record_of (v : Msgpack.t) : (record, Err.t) result =
  match v with
  | Msgpack.Map pairs ->
    (match () with
     | () when String.length (Msgpack.encode v) > Caps.record_max ->
       Error (Err.Oversized Gate_core.Record_over)
     | () ->
       List.fold_left
         (fun acc (k, w) ->
           Result.bind acc (fun fields ->
             Result.map (fun field -> field :: fields) (field_of k w)))
         (Ok []) pairs
       |> Result.map List.rev)
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Str _ | Msgpack.Bin _ | Msgpack.Arr _
  | Msgpack.Ext (_, _) -> Error bad_shape

let time_of (v : Msgpack.t) : (time, Err.t) result =
  match v with
  | Msgpack.Int n ->
    (match () with
     | () when n >= 0 -> Ok (Seconds n)
     | () -> Error bad_shape)
  | Msgpack.Ext (0, payload) when String.length payload = 8 ->
    Result.bind
      (Reader.u32be (Reader.of_string payload)
       |> Result.map_error (fun (_ : Reader.error) -> bad_shape))
      (fun (sec, r1) ->
        Result.bind
          (Reader.u32be r1
           |> Result.map_error (fun (_ : Reader.error) -> bad_shape))
          (fun (nsec, (_ : Reader.t)) ->
            match () with
            | () when nsec < 1_000_000_000 -> Ok (Event_time { sec; nsec })
            | () -> Error bad_shape))
  | Msgpack.Ext (_, _) -> Error bad_shape
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Uint64_edge _ | Msgpack.Float _
  | Msgpack.Str _ | Msgpack.Bin _ | Msgpack.Arr _ | Msgpack.Map _ ->
    Error bad_shape

(* Entry time slot: a bare time, or the fluent-bit v2 [time, metadata]
   wrapper with an empty metadata map (non-empty is a typed reject:
   nothing may pass this gate that it cannot re-emit). *)
let time_slot_of (v : Msgpack.t) : (time, Err.t) result =
  match v with
  | Msgpack.Arr [ t; Msgpack.Map [] ] -> time_of t
  | Msgpack.Arr _ -> Error bad_shape
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Str _ | Msgpack.Bin _ | Msgpack.Map _
  | Msgpack.Ext (_, _) -> time_of v

(* One Forward or PackedForward entry: [time-slot, record]. *)
let entry_of (v : Msgpack.t) : (time * record, Err.t) result =
  match v with
  | Msgpack.Arr [ slot; rec_v ] ->
    Result.bind (time_slot_of slot) (fun time ->
      Result.map (fun record -> (time, record)) (record_of rec_v))
  | Msgpack.Arr _ -> Error bad_shape
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Str _ | Msgpack.Bin _ | Msgpack.Map _
  | Msgpack.Ext (_, _) -> Error bad_shape

let tag_of (v : Msgpack.t) : (string, Err.t) result =
  match v with
  | Msgpack.Str s ->
    (match () with
     | () when String.length s = 0 -> Error bad_shape
     | () when String.length s > Caps.tag_max ->
       Error (Err.Oversized Gate_core.Tag_over)
     | () ->
       Utf8.validate s
       |> Result.map_error (fun (u : Gate_core.utf8_error) -> Err.Bad_utf8 u)
       |> Result.map (fun () -> s))
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Bin _ | Msgpack.Arr _ | Msgpack.Map _
  | Msgpack.Ext (_, _) -> Error bad_shape

(* Options are carried raw (M11 parses chunk); the element must be a
   map, and that is the only shape rule at this layer. *)
let options_of (v : Msgpack.t) : (options, Err.t) result =
  match v with
  | Msgpack.Map pairs -> Ok pairs
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Str _ | Msgpack.Bin _ | Msgpack.Arr _
  | Msgpack.Ext (_, _) -> Error bad_shape

let message_of (tag : string) (time_v : Msgpack.t) (record_v : Msgpack.t)
    (opts : options) : (frame * options, Err.t) result =
  Result.bind (time_of time_v) (fun time ->
    Result.map
      (fun record -> (Message { tag; time; record }, opts))
      (record_of record_v))

let forward_of (tag : string) (items : Msgpack.t list) (opts : options) :
    (frame * options, Err.t) result =
  List.fold_left
    (fun acc item ->
      Result.bind acc (fun entries ->
        Result.map (fun entry -> entry :: entries) (entry_of item)))
    (Ok []) items
  |> Result.map (fun entries ->
       (Forward { tag; entries = List.rev entries }, opts))

let compressed_key : Msgpack.t = Msgpack.Str "compressed"

(* PackedForward envelope.  "compressed": "gzip" is the
   CompressedPackedForward reject; "text" is the spec's explicit
   uncompressed marker; any other value is an unknown shape. *)
let packed_of (tag : string) (body : string) (opts : options) :
    (frame * options, Err.t) result =
  let plain = Ok (Packed_forward { tag; entries_bytes = body }, opts) in
  Option.fold ~none:plain
    ~some:(fun (v : Msgpack.t) ->
      match v with
      | Msgpack.Str s ->
        (match () with
         | () when s = "text" -> plain
         | () when s = "gzip" ->
           Error (Err.Malformed Gate_core.Compressed_unsupported)
         | () -> Error bad_shape)
      | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
      | Msgpack.Float _ | Msgpack.Bin _ | Msgpack.Arr _ | Msgpack.Map _
      | Msgpack.Ext (_, _) -> Error bad_shape)
    (List.assoc_opt compressed_key opts)

(* What the second top-level element says the mode is.  Uint64_edge
   and Float ride Message_time so their reject happens in [time_of]
   with the other time rules. *)
type mode =
  | Fwd_entries of Msgpack.t list
  | Packed_body of string
  | Message_time
  | Bad_second

let mode_of (second : Msgpack.t) : mode =
  match second with
  | Msgpack.Arr items -> Fwd_entries items
  | Msgpack.Str b | Msgpack.Bin b -> Packed_body b
  | Msgpack.Int _ | Msgpack.Ext (_, _) | Msgpack.Uint64_edge _
  | Msgpack.Float _ -> Message_time
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Map _ -> Bad_second

let body (tag : string) (rest : Msgpack.t list) :
    (frame * options, Err.t) result =
  match rest with
  | [] -> Error bad_shape
  | [ second ] ->
    (match mode_of second with
     | Fwd_entries items -> forward_of tag items []
     | Packed_body b -> packed_of tag b []
     | Message_time | Bad_second -> Error bad_shape)
  | [ second; third ] ->
    (match mode_of second with
     | Fwd_entries items -> Result.bind (options_of third) (forward_of tag items)
     | Packed_body b -> Result.bind (options_of third) (packed_of tag b)
     | Message_time -> message_of tag second third []
     | Bad_second -> Error bad_shape)
  | [ second; third; fourth ] ->
    (match mode_of second with
     | Message_time ->
       Result.bind (options_of fourth) (message_of tag second third)
     | Fwd_entries _ | Packed_body _ | Bad_second -> Error bad_shape)
  | _ :: _ :: _ :: _ :: _ -> Error bad_shape

let classify (top : Msgpack.t) : (frame * options, Err.t) result =
  match top with
  | Msgpack.Arr (tag_v :: rest) ->
    Result.bind (tag_of tag_v) (fun tag -> body tag rest)
  | Msgpack.Arr [] -> Error bad_shape
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Str _ | Msgpack.Bin _ | Msgpack.Map _
  | Msgpack.Ext (_, _) -> Error bad_shape

(* One complete frame's bytes to a typed frame plus its raw options.
   A Packed_forward frame is shape-checked at the envelope only here;
   [events] completes its classification entry by entry. *)
let decode (s : string) : (frame * options, Err.t) result =
  Result.bind (Msgpack.decode s |> Result.map_error Err.of_msgpack) classify

let events (f : frame) : (event list, Err.t) result =
  match f with
  | Message e -> Ok [ e ]
  | Forward { tag; entries } ->
    Ok (List.map (fun (time, record) -> { tag; time; record }) entries)
  | Packed_forward { tag; entries_bytes } ->
    let rec unpack (acc : event list) (count : int) (r : Reader.t) :
        (event list, Err.t) result =
      match () with
      | () when Reader.remaining r = 0 -> Ok (List.rev acc)
      | () when count >= Caps.entries_max ->
        Error (Err.Oversized Gate_core.Record_over)
      | () ->
        Result.bind
          (Msgpack.decode_one r |> Result.map_error Err.of_msgpack)
          (fun (v, r') ->
            Result.bind (entry_of v) (fun (time, record) ->
              unpack ({ tag; time; record } :: acc) (count + 1) r'))
    in
    unpack [] 0 (Reader.of_string entries_bytes)
