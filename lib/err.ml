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
