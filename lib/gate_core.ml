(* The one record-lifecycle semantics, shared verbatim between the daemon
   (lib/) and the model checker (model/ via copy_files). The hazard
   stages (Crashed, an unscrubbed emit of a sensitive record) are
   representable in these types on purpose: the model proves that [step]
   never reaches them, so safety is a checked property of this code, not
   an artifact of an encoding that cannot say "leak". *)

type malformed_reason =
  | Bad_msgpack
  | Bad_frame_shape
  | Compressed_unsupported
  | Duplicate_key

type cap_violation =
  | Frame_over
  | Record_over
  | Depth_over
  | Tag_over

type utf8_error =
  | Bad_byte
  | Overlong
  | Surrogate
  | Out_of_range
  | Truncated

(* What arrived, as ground truth. [dirty] means at least one detector
   matches somewhere in the decoded record. *)
type input_class =
  | Valid of { dirty : bool }
  | Malformed of malformed_reason
  | Oversized of cap_violation
  | Bad_utf8 of utf8_error

type dead_reason =
  | Dead_malformed of malformed_reason
  | Dead_oversized of cap_violation
  | Dead_bad_utf8 of utf8_error

type outcome =
  | Emit of { scrubbed : bool }
  | Dead_letter of dead_reason

(* Lifecycle stage of one record inside the gate. *)
type stage =
  | Ingested
  | Classified
  | Scanned of { dirty : bool }
  | Emitted of { scrubbed : bool }
  | Dead of dead_reason
  | Crashed

type world = {
  input : input_class;
  stage : stage;
}

(* The routing decision for a classified record. Total: every input
   class has exactly one outcome, and there is no exception path. *)
let route (c : input_class) : outcome =
  match c with
  | Valid { dirty } -> Emit { scrubbed = dirty }
  | Malformed r -> Dead_letter (Dead_malformed r)
  | Oversized v -> Dead_letter (Dead_oversized v)
  | Bad_utf8 e -> Dead_letter (Dead_bad_utf8 e)

(* One lifecycle step. Total and deterministic; terminals are fixpoints.
   Crashed is a fixpoint too: no arm steps into it, and the model holds
   that closed (S2 plus the cube sweep in test_correspondence). *)
let step (w : world) : world =
  match w.stage with
  | Ingested -> { w with stage = Classified }
  | Classified ->
    (match w.input with
     | Valid { dirty } -> { w with stage = Scanned { dirty } }
     | Malformed r -> { w with stage = Dead (Dead_malformed r) }
     | Oversized v -> { w with stage = Dead (Dead_oversized v) }
     | Bad_utf8 e -> { w with stage = Dead (Dead_bad_utf8 e) })
  | Scanned { dirty } -> { w with stage = Emitted { scrubbed = dirty } }
  | Emitted s -> { w with stage = Emitted s }
  | Dead r -> { w with stage = Dead r }
  | Crashed -> { w with stage = Crashed }

(* Tags for metrics labels, operator views, and witness printing.
   Exhaustive: a new constructor without a tag is a compile error. *)
let malformed_tag (r : malformed_reason) : string =
  match r with
  | Bad_msgpack -> "bad_msgpack"
  | Bad_frame_shape -> "bad_frame_shape"
  | Compressed_unsupported -> "compressed_unsupported"
  | Duplicate_key -> "duplicate_key"

let cap_tag (v : cap_violation) : string =
  match v with
  | Frame_over -> "frame_over"
  | Record_over -> "record_over"
  | Depth_over -> "depth_over"
  | Tag_over -> "tag_over"

let utf8_tag (e : utf8_error) : string =
  match e with
  | Bad_byte -> "bad_byte"
  | Overlong -> "overlong"
  | Surrogate -> "surrogate"
  | Out_of_range -> "out_of_range"
  | Truncated -> "truncated"

let reason_tag (r : dead_reason) : string =
  match r with
  | Dead_malformed m -> "malformed." ^ malformed_tag m
  | Dead_oversized v -> "oversized." ^ cap_tag v
  | Dead_bad_utf8 e -> "bad_utf8." ^ utf8_tag e

let class_tag (c : input_class) : string =
  match c with
  | Valid { dirty } -> if dirty then "valid.dirty" else "valid.clean"
  | Malformed m -> "malformed." ^ malformed_tag m
  | Oversized v -> "oversized." ^ cap_tag v
  | Bad_utf8 e -> "bad_utf8." ^ utf8_tag e

(* Finite menus, shared by the model frame and the correspondence gate. *)
let all_malformed : malformed_reason list =
  [ Bad_msgpack; Bad_frame_shape; Compressed_unsupported; Duplicate_key ]

let all_caps : cap_violation list =
  [ Frame_over; Record_over; Depth_over; Tag_over ]

let all_utf8 : utf8_error list =
  [ Bad_byte; Overlong; Surrogate; Out_of_range; Truncated ]

let all_reasons : dead_reason list =
  List.map (fun m -> Dead_malformed m) all_malformed
  @ List.map (fun v -> Dead_oversized v) all_caps
  @ List.map (fun e -> Dead_bad_utf8 e) all_utf8

let all_inputs : input_class list =
  [ Valid { dirty = false }; Valid { dirty = true } ]
  @ List.map (fun m -> Malformed m) all_malformed
  @ List.map (fun v -> Oversized v) all_caps
  @ List.map (fun e -> Bad_utf8 e) all_utf8
