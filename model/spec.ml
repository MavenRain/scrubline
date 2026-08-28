(* The specification suite. Positive specs must hold at Source in the
   Gate frame; negative controls must fail there; the Filter-frame
   controls must hold in the Filter frame, or the positive specs are
   vacuously true on an encoding that cannot express the hazards. A
   checker that passes a negative control is broken; the runner treats
   that as a failure of the suite itself. *)

type frame_id =
  | Gate
  | Filter

let frame_tag (f : frame_id) : string =
  match f with
  | Gate -> "gate"
  | Filter -> "filter"

type spec = {
  frame : frame_id;
  name : string;
  formula : (Frame.atom, Frame.agent) Ctlk.form;
  expected : bool;
}

let g (name : string) (formula : (Frame.atom, Frame.agent) Ctlk.form) : spec =
  { frame = Gate; name; formula; expected = true }

let ng (name : string) (formula : (Frame.atom, Frame.agent) Ctlk.form) : spec =
  { frame = Gate; name; formula; expected = false }

let ft (name : string) (formula : (Frame.atom, Frame.agent) Ctlk.form) : spec =
  { frame = Filter; name; formula; expected = true }

let specs : spec list =
  let open Ctlk in
  [ (* S1: no live sensitive value leaves the gate. *)
    g "s1-leak-safety" (Ag (Imp (Atom Frame.Emitted_any, Atom Frame.Safe)));
    (* S2: the crash stage is representable and unreachable. *)
    g "s2-no-crash" (Ag (Not (Atom Frame.Crashed_a)));
    (* S3: a malformed record never emits, on any future. *)
    g "s3-malformed-contained"
      (Ag (Imp (Atom Frame.Is_malformed, Ag (Not (Atom Frame.Emitted_any)))));
    (* S4: no silent drop; every record terminates as emit or DLQ. *)
    g "s4-no-silent-drop"
      (Ag
         (Imp
            ( Atom Frame.Is_record,
              Af (Or (Atom Frame.Emitted_any, Atom Frame.Dead_any)) )));
    (* S5: a dirty record that emits is scrubbed. *)
    g "s5-dirty-scrubbed"
      (Ag
         (Imp
            ( And (Atom Frame.Dirty, Atom Frame.Emitted_any),
              Atom Frame.Emitted_scrubbed )));
    (* S6: downstream needs no scanner of its own. Extensionally this
       coincides with S1: the Downstream view partitions worlds into
       emitted vs pending, so K_downstream Safe is the single bit "every
       emitted world is Safe" and no step or route edit separates the
       two verdicts. S6 stays because it pins the epistemic reading
       through the actual Know machinery, and F3 exhibits the frame
       where that knowledge fails. *)
    g "s6-downstream-knows-safe"
      (Ag
         (Imp
            ( Atom Frame.Emitted_any,
              Know (Frame.Downstream, Atom Frame.Safe) )));
    (* S9: no deadlock; terminals self-loop. Known limit: [gate_next]
       is a syntactic singleton (every arm returns a one-element list),
       so no mutation of [Gate_core.step] can falsify this formula; its
       content is the self-loop convention itself, held closed by the
       cube sweep in test_correspondence. *)
    g "s9-no-deadlock" (Ag (Ex Tt));
    (* S10: the gate does not mangle clean logs. *)
    g "s10-clean-identity"
      (Ag
         (Imp
            ( And (Atom Frame.Clean_valid, Atom Frame.Emitted_any),
              Atom Frame.Emitted_unscrubbed )))
  ]
  (* S7: the reason counters are enough for the operator to know why a
     record died. *)
  @ List.map
      (fun grp ->
        g
          ("s7-operator-knows-" ^ Frame.group_tag grp)
          Ctlk.(
            Ag
              (Imp
                 ( Atom (Frame.Dead_in grp),
                   Know (Frame.Operator, Atom (Frame.Dead_in grp)) ))))
      Frame.all_groups
  (* S8: each parse path reaches exactly the terminal route prescribes. *)
  @ List.map
      (fun i ->
        g
          ("s8-terminal-" ^ Gate_core.class_tag i)
          (Ctlk.Ef (Ctlk.Atom (Frame.Routed_terminal i))))
      Gate_core.all_inputs
  (* Negative controls: each must come out false, with a witness. *)
  @ [ ng "ng1-dirty-unreachable" (Ag (Not (Atom Frame.Dirty)));
      ng "ng2-instant-emit" (Ex (Atom Frame.Emitted_any));
      (* The metrics surface cannot see the payload. *)
      ng "ng3-metrics-see-payload"
        (Ag
           (Imp
              ( Atom Frame.Emitted_any,
                Know (Frame.Operator, Atom Frame.Dirty) )));
      ng "ng4-leak-reachable"
        (Ef (And (Atom Frame.Dirty, Atom Frame.Emitted_unscrubbed)))
    ]
  (* Filter-frame controls: the hazards are reachable in the regex-in-a-
     crashy-agent design, so the Gate-frame verdicts are not vacuous. *)
  @ [ ft "f1-under-redaction-reachable"
        (Ef (And (Atom Frame.Dirty, Atom Frame.Emitted_unscrubbed)));
      ft "f2-crash-reachable" (Ef (Atom Frame.Crashed_a));
      ft "f3-downstream-cannot-know"
        (Ef
           (And
              ( Atom Frame.Emitted_any,
                Not (Know (Frame.Downstream, Atom Frame.Safe)) )));
      (* F4: S3's hazard. A filter that cannot parse still forwards. *)
      ft "f4-malformed-passthrough-reachable"
        (Ef (And (Atom Frame.Is_malformed, Atom Frame.Emitted_any)));
      (* F5: the oversized clause of [safe]. A filter that never
         measures its input forwards the allocation bomb. *)
      ft "f5-oversized-passthrough-reachable"
        (Ef (And (Atom Frame.Is_oversized, Atom Frame.Emitted_any)));
      (* F6: S4's hazard. A crashed agent holds the record forever:
         some future never reaches emit or DLQ. *)
      ft "f6-hang-reachable"
        (Ef
           (And
              ( Atom Frame.Is_record,
                Not (Af (Or (Atom Frame.Emitted_any, Atom Frame.Dead_any)))
              )))
    ]

type outcome = {
  spec : spec;
  got : bool;
}

let run_all () : int * int * outcome list =
  let gsys = Frame.gate_system () in
  let fsys = Frame.filter_system () in
  let sys_of (f : frame_id) =
    match f with
    | Gate -> gsys
    | Filter -> fsys
  in
  let outcomes =
    List.map
      (fun s ->
        { spec = s;
          got = Ctlk.holds_at (sys_of s.frame) Frame.den s.formula Frame.Source
        })
      specs
  in
  (Topos.size gsys.Ctlk.space, Topos.size fsys.Ctlk.space, outcomes)

let mismatches (outcomes : outcome list) : outcome list =
  List.filter (fun o -> not (Bool.equal o.got o.spec.expected)) outcomes
