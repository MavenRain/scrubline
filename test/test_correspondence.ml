(* Model-code correspondence: an independent hand-written mirror of the
   routing table; the step orbit against route for every input; a
   totality sweep of step over the full stage-input cube (terminals are
   fixpoints, the input never mutates, nothing steps into Crashed); and
   the reachable-state counts of both frames pinned. The mirror is
   deliberately duplicated logic: a route edit that desynchronizes from
   this table turns the gate red. *)

module Gc = Gate_core

let mirror (i : Gc.input_class) : Gc.outcome =
  match i with
  | Gc.Valid { dirty = false } -> Gc.Emit { scrubbed = false }
  | Gc.Valid { dirty = true } -> Gc.Emit { scrubbed = true }
  | Gc.Malformed m -> Gc.Dead_letter (Gc.Dead_malformed m)
  | Gc.Oversized v -> Gc.Dead_letter (Gc.Dead_oversized v)
  | Gc.Bad_utf8 e -> Gc.Dead_letter (Gc.Dead_bad_utf8 e)

let show_outcome (o : Gc.outcome) : string =
  match o with
  | Gc.Emit { scrubbed } -> if scrubbed then "emit.scrubbed" else "emit.unscrubbed"
  | Gc.Dead_letter r -> "dead." ^ Gc.reason_tag r

let rec orbit (fuel : int) (w : Gc.world) : Gc.world =
  let n = Gc.step w in
  if fuel = 0 || Stdlib.compare n w = 0 then w else orbit (fuel - 1) n

let terminal_stage_of_outcome (o : Gc.outcome) : Gc.stage =
  match o with
  | Gc.Emit { scrubbed } -> Gc.Emitted { scrubbed }
  | Gc.Dead_letter r -> Gc.Dead r

let menu_errors : string list =
  let expect (name : string) (got : int) (want : int) : string list =
    if got = want then []
    else [ Printf.sprintf "menu %s: %d, want %d" name got want ]
  in
  expect "malformed" (List.length Gc.all_malformed) 4
  @ expect "caps" (List.length Gc.all_caps) 4
  @ expect "utf8" (List.length Gc.all_utf8) 5
  @ expect "inputs" (List.length Gc.all_inputs) 15
  @ expect "reasons" (List.length Gc.all_reasons) 13

let route_errors : string list =
  List.concat_map
    (fun i ->
      let got = Gc.route i in
      let want = mirror i in
      if Stdlib.compare got want = 0 then []
      else
        [ Printf.sprintf "route %s: %s, mirror says %s" (Gc.class_tag i)
            (show_outcome got) (show_outcome want)
        ])
    Gc.all_inputs

let orbit_errors : string list =
  List.concat_map
    (fun i ->
      let final = orbit 8 { Gc.input = i; Gc.stage = Gc.Ingested } in
      let want = terminal_stage_of_outcome (Gc.route i) in
      if Stdlib.compare final.Gc.stage want = 0 then []
      else [ Printf.sprintf "orbit %s: lands off route" (Gc.class_tag i) ])
    Gc.all_inputs

let all_stages : Gc.stage list =
  [ Gc.Ingested; Gc.Classified; Gc.Scanned { dirty = false };
    Gc.Scanned { dirty = true }; Gc.Emitted { scrubbed = false };
    Gc.Emitted { scrubbed = true } ]
  @ List.map (fun r -> Gc.Dead r) Gc.all_reasons
  @ [ Gc.Crashed ]

let is_terminal (s : Gc.stage) : bool =
  match s with
  | Gc.Emitted _ | Gc.Dead _ | Gc.Crashed -> true
  | Gc.Ingested | Gc.Classified | Gc.Scanned _ -> false

let cube : Gc.world list =
  List.concat_map
    (fun i -> List.map (fun s -> { Gc.input = i; Gc.stage = s }) all_stages)
    Gc.all_inputs

let cube_errors : string list =
  List.concat_map
    (fun (w : Gc.world) ->
      let n = Gc.step w in
      let input_kept =
        if Stdlib.compare n.Gc.input w.Gc.input = 0 then []
        else [ "step mutates input at " ^ Gc.class_tag w.Gc.input ]
      in
      let terminal_fixed =
        if is_terminal w.Gc.stage && Stdlib.compare n w <> 0 then
          [ "terminal moves: " ^ Gc.class_tag w.Gc.input ]
        else []
      in
      let no_crash_entry =
        match n.Gc.stage with
        | Gc.Crashed ->
          (match w.Gc.stage with
           | Gc.Crashed -> []
           | Gc.Ingested | Gc.Classified | Gc.Scanned _ | Gc.Emitted _
           | Gc.Dead _ -> [ "step reaches crash" ])
        | Gc.Ingested | Gc.Classified | Gc.Scanned _ | Gc.Emitted _
        | Gc.Dead _ -> []
      in
      input_kept @ terminal_fixed @ no_crash_entry)
    cube

let size_errors : string list =
  let gsys = Frame.gate_system () in
  let fsys = Frame.filter_system () in
  let expect (name : string) (got : int) (want : int) : string list =
    if got = want then []
    else [ Printf.sprintf "%s states: %d, want %d" name got want ]
  in
  expect "gate" (Topos.size gsys.Ctlk.space) 48
  @ expect "filter" (Topos.size fsys.Ctlk.space) 70

let () =
  let errors =
    menu_errors @ route_errors @ orbit_errors @ cube_errors @ size_errors
  in
  Printf.printf "correspondence: cube=%d inputs=%d\n" (List.length cube)
    (List.length Gc.all_inputs);
  match errors with
  | [] -> print_endline "test_correspondence: PASS"
  | _ :: _ ->
    List.iter (fun e -> print_endline ("  " ^ e)) errors;
    print_endline "test_correspondence: FAIL";
    exit 1
