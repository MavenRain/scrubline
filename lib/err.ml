(* M5: the one bridge from Phase B decode errors to the routing currency.
   Every decoder failure names exactly one [Gate_core.input_class]
   constructor, so classification is a total fold over this type and the
   model's source fan-out covers every real error path by construction. *)

type t =
  | Malformed of Gate_core.malformed_reason
  | Oversized of Gate_core.cap_violation
  | Bad_utf8 of Gate_core.utf8_error

let to_input_class (e : t) : Gate_core.input_class =
  match e with
  | Malformed r -> Gate_core.Malformed r
  | Oversized v -> Gate_core.Oversized v
  | Bad_utf8 u -> Gate_core.Bad_utf8 u

(* Metrics label; rides [Gate_core.class_tag] so the daemon and the model
   print the same vocabulary. *)
let tag (e : t) : string = Gate_core.class_tag (to_input_class e)

(* M10: the msgpack decoder's error vocabulary folded onto the model's
   menus.  string_max and entries_max are record-dimension caps, so
   Str_over and Count_over land on Record_over; the frame dimension
   (Frame_over) belongs to ingress (M20/M21), never to the decoder. *)
let of_msgpack (e : Msgpack.error) : t =
  match e with
  | Msgpack.Reserved_lead _ | Msgpack.Truncated _ | Msgpack.Negative_count _
  | Msgpack.Int64_negative_edge _ | Msgpack.Trailing _ ->
    Malformed Gate_core.Bad_msgpack
  | Msgpack.Duplicate_key _ -> Malformed Gate_core.Duplicate_key
  | Msgpack.Depth_over _ -> Oversized Gate_core.Depth_over
  | Msgpack.Str_over _ | Msgpack.Count_over _ ->
    Oversized Gate_core.Record_over
