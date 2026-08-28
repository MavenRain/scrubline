(* Spec-suite gate: one line per spec, a witness under every
   expected-false spec (and under any mismatch), exit 1 on mismatch. *)

let show_witness (w : Frame.world Witness.witness) : string =
  match w with
  | Witness.Path p ->
    "path " ^ String.concat " -> " (List.map Frame.show_world p)
  | Witness.Successors ss ->
    "successors "
    ^ String.concat "; "
        (List.map
           (fun (s, b) -> Frame.show_world s ^ "=" ^ Bool.to_string b)
           ss)
  | Witness.Confusion (a, b) ->
    "confusion " ^ Frame.show_world a ^ " ~ " ^ Frame.show_world b
  | Witness.At_state (s, b) ->
    "at " ^ Frame.show_world s ^ " verdict " ^ Bool.to_string b

let () =
  let gate_n, filter_n, outcomes = Spec.run_all () in
  Printf.printf "states gate=%d filter=%d specs=%d\n" gate_n filter_n
    (List.length outcomes);
  let gsys = Frame.gate_system () in
  let fsys = Frame.filter_system () in
  List.iter
    (fun (o : Spec.outcome) ->
      let ok = Bool.equal o.Spec.got o.Spec.spec.Spec.expected in
      Printf.printf "%s %s expected=%b got=%b %s\n"
        (Spec.frame_tag o.Spec.spec.Spec.frame)
        o.Spec.spec.Spec.name o.Spec.spec.Spec.expected o.Spec.got
        (if ok then "PASS" else "FAIL");
      let sys =
        match o.Spec.spec.Spec.frame with
        | Spec.Gate -> gsys
        | Spec.Filter -> fsys
      in
      if (not o.Spec.spec.Spec.expected) || not ok then
        Printf.printf "  %s\n"
          (show_witness
             (Witness.explain sys Frame.den o.Spec.spec.Spec.formula
                Frame.Source)))
    outcomes;
  match Spec.mismatches outcomes with
  | [] -> print_endline "test_model: PASS"
  | _ :: _ ->
    print_endline "test_model: FAIL";
    exit 1
