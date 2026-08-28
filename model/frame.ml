(* The interpreted system: one record's journey through the gate, as a
   finite frame for the CTLK checker. Source fans out to every input
   class (the adversary's choice); the Gate frame then steps with the
   shared Gate_core.step, so the checked transitions are the shipped
   routing semantics. The Filter frame is the negative control: a
   byte-regex filter inside a crashy C agent, where a missed redaction,
   a passthrough, and a crash are reachable. The positive specs are
   meaningful only because the Filter frame proves the hazards
   representable. *)

module Gc = Gate_core
module T = Topos

type agent =
  | Downstream
  | Operator

let agents : agent list = [ Downstream; Operator ]

type world =
  | Source
  | Rec of Gc.world

let compare_world (a : world) (b : world) : int = Stdlib.compare a b

let ingested (i : Gc.input_class) : world =
  Rec { Gc.input = i; Gc.stage = Gc.Ingested }

let gate_next (w : world) : world list =
  match w with
  | Source -> List.map ingested Gc.all_inputs
  | Rec r -> [ Rec (Gc.step r) ]

(* Filter frame, classified dispatch. Malformed input can crash the
   process, pass through unparsed, or land in a dead pile; oversized
   input can crash the allocator or sail through a filter that never
   measures it; invalid UTF-8 sails past a byte regex. Every sensitive
   class must reach an unscrubbed emit somewhere in this frame, or the
   corresponding clause of [safe] is vacuous (F4/F5 pin this). *)
let filter_classified (r : Gc.world) : Gc.world list =
  let open Gc in
  match r.input with
  | Valid { dirty } -> [ { r with stage = Scanned { dirty } } ]
  | Malformed m ->
    [ { r with stage = Crashed };
      { r with stage = Emitted { scrubbed = false } };
      { r with stage = Dead (Dead_malformed m) } ]
  | Oversized v ->
    [ { r with stage = Crashed };
      { r with stage = Emitted { scrubbed = false } };
      { r with stage = Dead (Dead_oversized v) } ]
  | Bad_utf8 e ->
    [ { r with stage = Emitted { scrubbed = false } };
      { r with stage = Dead (Dead_bad_utf8 e) } ]

let filter_step (r : Gc.world) : Gc.world list =
  let open Gc in
  match r.stage with
  | Ingested -> [ { r with stage = Classified } ]
  | Classified -> filter_classified r
  | Scanned { dirty } ->
    if dirty then
      [ { r with stage = Emitted { scrubbed = true } };
        { r with stage = Emitted { scrubbed = false } } ]
    else [ { r with stage = Emitted { scrubbed = false } } ]
  | Emitted s -> [ { r with stage = Emitted s } ]
  | Dead d -> [ { r with stage = Dead d } ]
  | Crashed -> [ { r with stage = Crashed } ]

let filter_next (w : world) : world list =
  match w with
  | Source -> List.map ingested Gc.all_inputs
  | Rec r -> List.map (fun s -> Rec s) (filter_step r)

(* Observation maps. Downstream sees only that a record was emitted:
   not the gate internals, not the DLQ, not the payload flags. The
   operator sees the metrics surface: the terminal stage including the
   scrub bit (the shipped counters split scrubbed from unscrubbed) and
   the dead-letter reason tag (and a crash, which is process-visible). *)
let view (ag : agent) (w : world) : string =
  match ag with
  | Downstream ->
    (match w with
     | Source -> "downstream:pending"
     | Rec r ->
       (match r.Gc.stage with
        | Gc.Emitted _ -> "downstream:emitted"
        | Gc.Ingested | Gc.Classified | Gc.Scanned _ | Gc.Dead _ | Gc.Crashed
          -> "downstream:pending"))
  | Operator ->
    (match w with
     | Source -> "operator:run"
     | Rec r ->
       (match r.Gc.stage with
        | Gc.Emitted { scrubbed } ->
          if scrubbed then "operator:emitted:scrubbed"
          else "operator:emitted:unscrubbed"
        | Gc.Dead d -> "operator:dlq:" ^ Gc.reason_tag d
        | Gc.Crashed -> "operator:crashed"
        | Gc.Ingested | Gc.Classified | Gc.Scanned _ -> "operator:run"))

(* Projections and stage predicates, total by exhaustive listing. *)
let stage_of (w : world) : Gc.stage option =
  match w with
  | Source -> None
  | Rec r -> Some r.Gc.stage

let input_of (w : world) : Gc.input_class option =
  match w with
  | Source -> None
  | Rec r -> Some r.Gc.input

(* The stdlib Option has no exists; the fold default is a plain value,
   so eagerness is not a concern here. *)
let opt_exists (p : 'a -> bool) (o : 'a option) : bool =
  Option.fold ~none:false ~some:p o

let on_stage (w : world) (p : Gc.stage -> bool) : bool =
  opt_exists p (stage_of w)

let on_input (w : world) (p : Gc.input_class -> bool) : bool =
  opt_exists p (input_of w)

let is_emitted (s : Gc.stage) : bool =
  match s with
  | Gc.Emitted _ -> true
  | Gc.Ingested | Gc.Classified | Gc.Scanned _ | Gc.Dead _ | Gc.Crashed -> false

(* Some scrub bit when the stage is an emit, None otherwise. *)
let emitted_flag (s : Gc.stage) : bool option =
  match s with
  | Gc.Emitted { scrubbed } -> Some scrubbed
  | Gc.Ingested | Gc.Classified | Gc.Scanned _ | Gc.Dead _ | Gc.Crashed -> None

let is_dead (s : Gc.stage) : bool =
  match s with
  | Gc.Dead _ -> true
  | Gc.Ingested | Gc.Classified | Gc.Scanned _ | Gc.Emitted _ | Gc.Crashed -> false

let is_crashed (s : Gc.stage) : bool =
  match s with
  | Gc.Crashed -> true
  | Gc.Ingested | Gc.Classified | Gc.Scanned _ | Gc.Emitted _ | Gc.Dead _ -> false

let input_dirty (i : Gc.input_class) : bool =
  match i with
  | Gc.Valid { dirty } -> dirty
  | Gc.Malformed _ | Gc.Oversized _ | Gc.Bad_utf8 _ -> false

let input_clean_valid (i : Gc.input_class) : bool =
  match i with
  | Gc.Valid { dirty } -> not dirty
  | Gc.Malformed _ | Gc.Oversized _ | Gc.Bad_utf8 _ -> false

let input_malformed (i : Gc.input_class) : bool =
  match i with
  | Gc.Malformed _ -> true
  | Gc.Valid _ | Gc.Oversized _ | Gc.Bad_utf8 _ -> false

let input_bad_utf8 (i : Gc.input_class) : bool =
  match i with
  | Gc.Bad_utf8 _ -> true
  | Gc.Valid _ | Gc.Oversized _ | Gc.Malformed _ -> false

let input_oversized (i : Gc.input_class) : bool =
  match i with
  | Gc.Oversized _ -> true
  | Gc.Valid _ | Gc.Malformed _ | Gc.Bad_utf8 _ -> false

type group =
  | G_malformed
  | G_oversized
  | G_bad_utf8

let all_groups : group list = [ G_malformed; G_oversized; G_bad_utf8 ]

let group_tag (g : group) : string =
  match g with
  | G_malformed -> "malformed"
  | G_oversized -> "oversized"
  | G_bad_utf8 -> "bad_utf8"

let group_of (d : Gc.dead_reason) : group =
  match d with
  | Gc.Dead_malformed _ -> G_malformed
  | Gc.Dead_oversized _ -> G_oversized
  | Gc.Dead_bad_utf8 _ -> G_bad_utf8

(* Safe: what downstream holds is either scrubbed or was really scanned
   clean. Every non-clean input class (dirty, malformed, invalid UTF-8,
   or oversized) is sensitive: an unscrubbed emit of any of them is the
   hazard, so a routing change that emits one must show up as a spec
   failure here, not slip through as an encoding gap. *)
let safe (w : world) : bool =
  let unscrubbed = on_stage w (fun s -> opt_exists not (emitted_flag s)) in
  let sensitive =
    on_input w (fun i ->
        input_dirty i || input_malformed i || input_bad_utf8 i
        || input_oversized i)
  in
  not (unscrubbed && sensitive)

(* Does this stage sit exactly where [route] says this record ends? *)
let terminal_matches (o : Gc.outcome) (s : Gc.stage) : bool =
  match o with
  | Gc.Emit { scrubbed } -> opt_exists (Bool.equal scrubbed) (emitted_flag s)
  | Gc.Dead_letter r ->
    (match s with
     | Gc.Dead r2 -> Stdlib.compare r r2 = 0
     | Gc.Ingested | Gc.Classified | Gc.Scanned _ | Gc.Emitted _ | Gc.Crashed
       -> false)

type atom =
  | Emitted_any
  | Emitted_scrubbed
  | Emitted_unscrubbed
  | Dead_any
  | Dead_in of group
  | Crashed_a
  | Is_record
  | Dirty
  | Clean_valid
  | Is_malformed
  | Is_oversized
  | Safe
  | Routed_terminal of Gc.input_class

let den (a : atom) : world T.sub =
 fun w ->
  match a with
  | Emitted_any -> on_stage w is_emitted
  | Emitted_scrubbed ->
    on_stage w (fun s -> opt_exists Fun.id (emitted_flag s))
  | Emitted_unscrubbed ->
    on_stage w (fun s -> opt_exists not (emitted_flag s))
  | Dead_any -> on_stage w is_dead
  | Dead_in g ->
    on_stage w (fun s ->
        match s with
        | Gc.Dead d -> Stdlib.compare (group_of d) g = 0
        | Gc.Ingested | Gc.Classified | Gc.Scanned _ | Gc.Emitted _
        | Gc.Crashed -> false)
  | Crashed_a -> on_stage w is_crashed
  | Is_record -> Option.is_some (stage_of w)
  | Dirty -> on_input w input_dirty
  | Clean_valid -> on_input w input_clean_valid
  | Is_malformed -> on_input w input_malformed
  | Is_oversized -> on_input w input_oversized
  | Safe -> safe w
  | Routed_terminal i ->
    on_input w (fun j -> Stdlib.compare i j = 0)
    && on_stage w (terminal_matches (Gc.route i))

let gate_system () : (world, agent) Ctlk.system =
  Ctlk.system_of compare_world gate_next Source agents view

let filter_system () : (world, agent) Ctlk.system =
  Ctlk.system_of compare_world filter_next Source agents view

let show_stage (s : Gc.stage) : string =
  match s with
  | Gc.Ingested -> "ingested"
  | Gc.Classified -> "classified"
  | Gc.Scanned { dirty } -> if dirty then "scanned.dirty" else "scanned.clean"
  | Gc.Emitted { scrubbed } ->
    if scrubbed then "emitted.scrubbed" else "emitted.unscrubbed"
  | Gc.Dead d -> "dead." ^ Gc.reason_tag d
  | Gc.Crashed -> "crashed"

let show_world (w : world) : string =
  match w with
  | Source -> "source"
  | Rec r -> Gc.class_tag r.Gc.input ^ "/" ^ show_stage r.Gc.stage
