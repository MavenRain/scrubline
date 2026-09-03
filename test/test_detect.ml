(* M12: framework tests.  The production matcher list is empty until
   M13, so every check here drives the framework through synthetic
   matchers passed explicitly.  Group I pins the empty production
   surface, so M13 has to flip those lines on purpose. *)

open Scrubline

let sp (d : Detect.detector) (a : int) (b : int) : Detect.span =
  { Detect.detector = d; start = a; stop = b }

let is_digit (c : char) : bool = '0' <= c && c <= '9'

(* The open run of digits, as a sum type rather than an option. *)
type run =
  | No_run
  | Run of int

(* Maximal ASCII digit runs of length [n] or more, stamped Pan. *)
let digits_run (n : int) : Detect.matcher =
  { Detect.emits = Detect.Pan;
    find =
      (fun s ->
        let close (start : int) (stop : int) (acc : (int * int) list) =
          match () with
          | () when stop - start >= n -> (start, stop) :: acc
          | () -> acc
        in
        let acc, run =
          Seq.fold_left
            (fun (acc, run) ((i : int), (c : char)) ->
              match run with
              | No_run -> (
                match () with
                | () when is_digit c -> (acc, Run i)
                | () -> (acc, No_run))
              | Run start -> (
                match () with
                | () when is_digit c -> (acc, Run start)
                | () -> (close start i acc, No_run)))
            ([], No_run) (String.to_seqi s)
        in
        (match run with
         | No_run -> acc
         | Run start -> close start (String.length s) acc)
        |> List.rev)
  }

(* Every occurrence start of [lit], overlapping occurrences included. *)
let literal ~(as_ : Detect.detector) (lit : string) : Detect.matcher =
  { Detect.emits = as_;
    find =
      (fun s ->
        let pat = List.of_seq (String.to_seq lit) in
        let n = String.length lit in
        let rec prefix (p : char list) (t : char list) : bool =
          match p with
          | [] -> true
          | pc :: ptl -> (
            match t with
            | [] -> false
            | tc :: ttl -> (
              match () with
              | () when pc = tc -> prefix ptl ttl
              | () -> false))
        in
        let rec go (i : int) (t : char list) (acc : (int * int) list) =
          match t with
          | [] -> acc
          | (_ : char) :: ttl ->
            let acc =
              match () with
              | () when n > 0 && prefix pat t -> (i, i + n) :: acc
              | () -> acc
            in
            go (i + 1) ttl acc
        in
        List.rev (go 0 (List.of_seq (String.to_seq s)) []))
  }

(* A matcher that returns the same pairs for any input. *)
let const ~(as_ : Detect.detector) (pairs : (int * int) list) : Detect.matcher =
  { Detect.emits = as_; find = (fun (_ : string) -> pairs) }

let marker : Detect.detector -> string -> string =
  fun d (_ : string) -> "<" ^ Detect.to_string d ^ ">"

let echo : Detect.detector -> string -> string =
  fun d m -> "<" ^ Detect.to_string d ^ ":" ^ m ^ ">"

let alphabet_only (s : string) : string =
  String.to_seq s
  |> Seq.filter (fun (c : char) -> is_digit c || c = '-')
  |> String.of_seq

let count_char (ch : char) (s : string) : int =
  Seq.fold_left
    (fun (n : int) (c : char) ->
      match () with
      | () when c = ch -> n + 1
      | () -> n)
    0 (String.to_seq s)

let rep (s : string) (spans : Detect.span list) : string =
  Detect.replace ~token:marker s spans

let tw (v : Msgpack.t) : Msgpack.t * Detect.span list =
  Detect.tree_with [ digits_run 4 ] ~token:marker v

let rw (r : Forward.record) : Forward.record * Detect.span list =
  Detect.record_with [ digits_run 4 ] ~token:marker r

(* Property sweep support.  A deterministic LCG, so the sweep is the
   same run to run and takes nothing from the environment. *)
let next (seed : int) : int = (seed * 1103515245 + 12345) land 0x3fffffff

(* A total remainder for a small non-negative [v] and a positive [m].
   Repeated subtraction avoids a bare mod on a value-dependent
   divisor.  Callers reduce [v] with a constant modulus first, so the
   recursion is a few dozen steps at most. *)
let rec rem_small (v : int) (m : int) : int =
  match () with
  | () when m <= 0 -> 0
  | () when v < m -> v
  | () -> rem_small (v - m) m

let alpha : char list = List.of_seq (String.to_seq "0123456789-")

let alpha_char (i : int) : char = Option.value ~default:'0' (List.nth_opt alpha i)

let detector_of (i : int) : Detect.detector =
  match () with
  | () when i = 0 -> Detect.Pan
  | () when i = 1 -> Detect.Ssn
  | () when i = 2 -> Detect.Aws_key
  | () when i = 3 -> Detect.Sol_pubkey
  | () -> Detect.Eth_address

type gcase = { s : string; cands : Detect.span list }

let rec gen_string (seed : int) (n : int) (acc : char list) : int * string =
  match () with
  | () when n <= 0 -> (seed, String.of_seq (List.to_seq (List.rev acc)))
  | () ->
    let seed = next seed in
    gen_string seed (n - 1) (alpha_char (seed mod 11) :: acc)

let rec gen_cands (seed : int) (len : int) (n : int) (acc : Detect.span list) :
    int * Detect.span list =
  match () with
  | () when n <= 0 -> (seed, List.rev acc)
  | () ->
    let s1 = next seed in
    let start = -2 + rem_small (s1 mod 64) (len + 5) in
    let s2 = next s1 in
    let stop = start - 1 + rem_small (s2 mod 64) (len - start + 5) in
    let s3 = next s2 in
    gen_cands s3 len (n - 1) (sp (detector_of (s3 mod 5)) start stop :: acc)

let rec gen_cases (seed : int) (n : int) (acc : gcase list) : gcase list =
  match () with
  | () when n <= 0 -> List.rev acc
  | () ->
    let s0 = next seed in
    let len = s0 mod 25 in
    let s1, str = gen_string s0 len [] in
    let s2 = next s1 in
    let s3, cands = gen_cands s2 len (s2 mod 7) [] in
    gen_cases s3 (n - 1) ({ s = str; cands } :: acc)

let cases : gcase list = gen_cases 20260912 300 []

let resolved (c : gcase) : Detect.span list =
  Detect.resolve ~len:(String.length c.s) c.cands

let well_formed_cands (c : gcase) : Detect.span list =
  List.filter (Detect.well_formed ~len:(String.length c.s)) c.cands

let ascending_disjoint (l : Detect.span list) : bool =
  List.fold_left
    (fun ((ok : bool), (edge : int)) (x : Detect.span) ->
      (ok && x.Detect.start >= edge, x.Detect.stop))
    (true, 0) l
  |> fst

let overlaps (a : Detect.span) (b : Detect.span) : bool =
  a.Detect.start < b.Detect.stop && b.Detect.start < a.Detect.stop

(* The input bytes that no resolved span covers. *)
let outside (s : string) (r : Detect.span list) : string =
  String.to_seqi s
  |> Seq.filter (fun ((i : int), (_ : char)) ->
       not
         (List.exists
            (fun (x : Detect.span) ->
              x.Detect.start <= i && i < x.Detect.stop)
            r))
  |> Seq.map (fun ((_ : int), (c : char)) -> c)
  |> String.of_seq

let covered (r : Detect.span list) : int =
  List.fold_left
    (fun (n : int) (x : Detect.span) -> n + (x.Detect.stop - x.Detect.start))
    0 r

let token_bytes (r : Detect.span list) : int =
  List.fold_left
    (fun (n : int) (x : Detect.span) ->
      n + String.length (marker x.Detect.detector ""))
    0 r

let sweep (p : gcase -> bool) : bool = List.for_all p cases

let checks : (string * bool) list =
  [ (* A. the detector table itself *)
    ( "priority follows the design table order",
      List.map Detect.priority
        [ Detect.Pan; Detect.Ssn; Detect.Aws_key; Detect.Sol_pubkey;
          Detect.Eth_address ]
      = [ 0; 1; 2; 3; 4 ] );
    ( "to_string names are pinned",
      List.map Detect.to_string
        [ Detect.Pan; Detect.Ssn; Detect.Aws_key; Detect.Sol_pubkey;
          Detect.Eth_address ]
      = [ "pan"; "ssn"; "aws_key"; "sol_pubkey"; "eth_address" ] );
    (* B. candidate hygiene *)
    ( "well_formed rejects a negative start",
      Detect.well_formed ~len:8 (sp Detect.Pan (-1) 3) = false );
    ( "well_formed rejects a stop past the end",
      Detect.well_formed ~len:8 (sp Detect.Pan 4 9) = false );
    ( "well_formed rejects an empty span",
      Detect.well_formed ~len:8 (sp Detect.Pan 3 3) = false );
    ( "well_formed rejects an inverted span",
      Detect.well_formed ~len:8 (sp Detect.Pan 5 2) = false );
    ( "well_formed accepts a span inside the string",
      Detect.well_formed ~len:8 (sp Detect.Pan 0 8) = true );
    (* C. overlap resolution *)
    ("resolve of nothing is nothing", Detect.resolve ~len:8 [] = []);
    ( "resolve keeps a lone well-formed span",
      Detect.resolve ~len:8 [ sp Detect.Ssn 2 5 ] = [ sp Detect.Ssn 2 5 ] );
    ( "leftmost beats a longer span that starts later",
      Detect.resolve ~len:12 [ sp Detect.Ssn 2 10; sp Detect.Pan 0 3 ]
      = [ sp Detect.Pan 0 3 ] );
    ( "same start: longest wins over higher priority",
      Detect.resolve ~len:8 [ sp Detect.Pan 0 3; sp Detect.Ssn 0 5 ]
      = [ sp Detect.Ssn 0 5 ] );
    ( "same start and length: priority decides",
      Detect.resolve ~len:8 [ sp Detect.Eth_address 0 4; sp Detect.Pan 0 4 ]
      = [ sp Detect.Pan 0 4 ] );
    ( "identical duplicates collapse to one",
      Detect.resolve ~len:8 [ sp Detect.Pan 0 3; sp Detect.Pan 0 3 ]
      = [ sp Detect.Pan 0 3 ] );
    ( "adjacent spans both survive",
      Detect.resolve ~len:8 [ sp Detect.Pan 0 2; sp Detect.Ssn 2 4 ]
      = [ sp Detect.Pan 0 2; sp Detect.Ssn 2 4 ] );
    ( "a one-byte overlap drops the later span",
      Detect.resolve ~len:8
        [ sp Detect.Pan 0 3; sp Detect.Ssn 2 5; sp Detect.Aws_key 3 6 ]
      = [ sp Detect.Pan 0 3; sp Detect.Aws_key 3 6 ] );
    ( "output is ascending even from reversed input",
      Detect.resolve ~len:8
        [ sp Detect.Pan 4 6; sp Detect.Ssn 2 4; sp Detect.Aws_key 0 2 ]
      = [ sp Detect.Aws_key 0 2; sp Detect.Ssn 2 4; sp Detect.Pan 4 6 ] );
    ( "ill-formed candidates drop and the rest stay",
      Detect.resolve ~len:6
        [ sp Detect.Pan (-1) 2; sp Detect.Ssn 0 2; sp Detect.Aws_key 5 3;
          sp Detect.Pan 3 5; sp Detect.Ssn 2 99 ]
      = [ sp Detect.Ssn 0 2; sp Detect.Pan 3 5 ] );
    ( "resolve is idempotent on a mixed list",
      (let mixed =
         [ sp Detect.Pan (-1) 2; sp Detect.Ssn 0 2; sp Detect.Aws_key 5 3;
           sp Detect.Pan 3 5; sp Detect.Ssn 2 99; sp Detect.Pan 1 4 ]
       in
       let once = Detect.resolve ~len:6 mixed in
       Detect.resolve ~len:6 once = once) );
    (* D. scanning through matchers *)
    ("no matchers find nothing", Detect.scan_with [] "1234 5678" = []);
    ( "a digit-run matcher finds both runs",
      Detect.scan_with [ digits_run 4 ] "id 1234 x 56789"
      = [ sp Detect.Pan 3 7; sp Detect.Pan 10 15 ] );
    ( "two matchers keep adjacent finds in order",
      Detect.scan_with
        [ literal ~as_:Detect.Aws_key "AKIA"; digits_run 4 ]
        "AKIA1234"
      = [ sp Detect.Aws_key 0 4; sp Detect.Pan 4 8 ] );
    ( "cross-matcher overlap resolves to the longest",
      Detect.scan_with [ digits_run 4; literal ~as_:Detect.Ssn "12" ] "123456"
      = [ sp Detect.Pan 0 6 ] );
    ( "the same span from two matchers resolves by priority",
      Detect.scan_with
        [ literal ~as_:Detect.Eth_address "12"; literal ~as_:Detect.Pan "12" ]
        "12"
      = [ sp Detect.Pan 0 2 ] );
    ( "overlapping literal occurrences keep the leftmost",
      Detect.scan_with [ literal ~as_:Detect.Pan "aa" ] "aaa"
      = [ sp Detect.Pan 0 2 ] );
    (* E. replacement *)
    ("no spans leaves the string alone", rep "a1234b" [] = "a1234b");
    ( "a span in the middle becomes one token",
      rep "a1234b" [ sp Detect.Pan 1 5 ] = "a<pan>b" );
    ("a span at the start becomes one token", rep "1234b" [ sp Detect.Pan 0 4 ] = "<pan>b");
    ("a span at the end becomes one token", rep "a1234" [ sp Detect.Pan 1 5 ] = "a<pan>");
    ("a whole-string span becomes one token", rep "1234" [ sp Detect.Pan 0 4 ] = "<pan>");
    ( "adjacent spans emit two tokens back to back",
      rep "12ab" [ sp Detect.Pan 0 2; sp Detect.Ssn 2 4 ] = "<pan><ssn>" );
    ( "the token function gets exactly the matched bytes",
      Detect.replace ~token:echo "x1234y" [ sp Detect.Pan 1 5 ]
      = "x<pan:1234>y" );
    ( "gap bytes copy through byte exact",
      rep "\xc3\xa91234\xc3\xa9" [ sp Detect.Pan 2 6 ]
      = "\xc3\xa9<pan>\xc3\xa9" );
    ( "replace resolves its own input first",
      (let s = "0123456789" in
       let messy =
         [ sp Detect.Ssn 6 4; sp Detect.Pan 2 5; sp Detect.Ssn 3 8;
           sp Detect.Aws_key 0 2; sp Detect.Pan (-1) 3;
           sp Detect.Eth_address 8 20 ]
       in
       rep s messy = rep s (Detect.resolve ~len:(String.length s) messy)) );
    ( "ill-formed spans alone leave the string alone",
      rep "abc" [ sp Detect.Pan (-1) 2; sp Detect.Pan 2 99; sp Detect.Pan 3 3 ]
      = "abc" );
    ("an empty string stays empty", rep "" [ sp Detect.Pan 0 1 ] = "");
    ( "a one-byte span at the start",
      rep "1ab" [ sp Detect.Pan 0 1 ] = "<pan>ab" );
    ( "a one-byte span in the middle",
      rep "a1b" [ sp Detect.Pan 1 2 ] = "a<pan>b" );
    ("a one-byte span at the end", rep "ab1" [ sp Detect.Pan 2 3 ] = "ab<pan>");
    (* F. property sweep over 300 generated cases *)
    ("the sweep generated 300 cases", List.length cases = 300);
    ( "sweep: every resolved span is well formed",
      sweep (fun c ->
        List.for_all
          (Detect.well_formed ~len:(String.length c.s))
          (resolved c)) );
    ( "sweep: resolved spans are ascending and disjoint",
      sweep (fun c -> ascending_disjoint (resolved c)) );
    ( "sweep: resolved is a subset of the well-formed candidates",
      sweep (fun c ->
        let wf = well_formed_cands c in
        List.for_all (fun x -> List.mem x wf) (resolved c)) );
    ( "sweep: resolve is idempotent",
      sweep (fun c ->
        let once = resolved c in
        Detect.resolve ~len:(String.length c.s) once = once) );
    ( "sweep: every dropped candidate overlaps a kept one",
      sweep (fun c ->
        let r = resolved c in
        List.for_all
          (fun x -> List.mem x r || List.exists (overlaps x) r)
          (well_formed_cands c)) );
    ( "sweep: no span byte survives the replacement",
      sweep (fun c ->
        alphabet_only (rep c.s c.cands) = outside c.s (resolved c)) );
    ( "sweep: one token per resolved span",
      sweep (fun c ->
        count_char '<' (rep c.s c.cands) = List.length (resolved c)) );
    ( "sweep: output length is input minus covered plus tokens",
      sweep (fun c ->
        let r = resolved c in
        String.length (rep c.s c.cands)
        = String.length c.s - covered r + token_bytes r) );
    ( "sweep: at least 50 cases resolved to a non-empty span list",
      List.length (List.filter (fun c -> resolved c <> []) cases) >= 50 );
    (* G. the tree walk *)
    ("tree: nil passes through", tw Msgpack.Nil = (Msgpack.Nil, []));
    ( "tree: bool passes through",
      tw (Msgpack.Bool true) = (Msgpack.Bool true, []) );
    ("tree: int passes through", tw (Msgpack.Int 1234) = (Msgpack.Int 1234, []));
    ( "tree: uint64 edge passes through",
      tw (Msgpack.Uint64_edge "12345678") = (Msgpack.Uint64_edge "12345678", [])
    );
    ("tree: float passes through", tw (Msgpack.Float 1.5) = (Msgpack.Float 1.5, []));
    ( "tree: a bin payload is never scanned",
      tw (Msgpack.Bin "1234") = (Msgpack.Bin "1234", []) );
    ( "tree: an ext payload is never scanned",
      tw (Msgpack.Ext (0, "1234")) = (Msgpack.Ext (0, "1234"), []) );
    ( "tree: a str value is scrubbed and reports its span",
      tw (Msgpack.Str "1234") = (Msgpack.Str "<pan>", [ sp Detect.Pan 0 4 ]) );
    ( "tree: a map key is scanned like its value",
      fst (tw (Msgpack.Map [ (Msgpack.Str "1234", Msgpack.Str "5678") ]))
      = Msgpack.Map [ (Msgpack.Str "<pan>", Msgpack.Str "<pan>") ] );
    ( "tree: map spans are key then value, offsets per string",
      snd (tw (Msgpack.Map [ (Msgpack.Str "a1234", Msgpack.Str "5678") ]))
      = [ sp Detect.Pan 1 5; sp Detect.Pan 0 4 ] );
    ( "tree: a non-str map key passes through",
      tw (Msgpack.Map [ (Msgpack.Int 1234, Msgpack.Str "1234") ])
      = (Msgpack.Map [ (Msgpack.Int 1234, Msgpack.Str "<pan>") ],
         [ sp Detect.Pan 0 4 ]) );
    ( "tree: nested arrays and maps recurse in tree order",
      tw
        (Msgpack.Arr
           [ Msgpack.Map [ (Msgpack.Str "a1234", Msgpack.Str "b") ];
             Msgpack.Str "5678" ])
      = ( Msgpack.Arr
            [ Msgpack.Map [ (Msgpack.Str "a<pan>", Msgpack.Str "b") ];
              Msgpack.Str "<pan>" ],
          [ sp Detect.Pan 1 5; sp Detect.Pan 0 4 ] ) );
    ( "tree: a clean tree comes back unchanged with no spans",
      (let clean =
         Msgpack.Arr
           [ Msgpack.Str "ab"; Msgpack.Int 1;
             Msgpack.Map [ (Msgpack.Str "k", Msgpack.Str "v") ] ]
       in
       tw clean = (clean, [])) );
    (* H. the record walk *)
    ( "record: the key is scrubbed and the value is tree-walked",
      fst (rw [ ("1234", Msgpack.Arr [ Msgpack.Str "x5678" ]) ])
      = [ ("<pan>", Msgpack.Arr [ Msgpack.Str "x<pan>" ]) ] );
    ( "record: spans are field order, key before value",
      snd (rw [ ("1234", Msgpack.Arr [ Msgpack.Str "x5678" ]) ])
      = [ sp Detect.Pan 0 4; sp Detect.Pan 1 5 ] );
    ( "record: no matchers is the identity",
      (let r = [ ("1234", Msgpack.Str "5678") ] in
       Detect.record_with [] ~token:marker r = (r, [])) );
    (* I. the production surface: Pan since M13, Ssn since M14,
       Aws_key since M15, Sol_pubkey since M16 *)
    ( "production matcher list is Pan, Ssn, Aws_key then Sol_pubkey at M16",
      List.map (fun (m : Detect.matcher) -> m.Detect.emits) Detect.matchers
      = [ Detect.Pan; Detect.Ssn; Detect.Aws_key; Detect.Sol_pubkey ] );
    ("production scan leaves a short digit run", Detect.scan "1234" = []);
    ( "production scan finds an SSN",
      Detect.scan "123-45-6789" = [ sp Detect.Ssn 0 11 ] );
    ( "production scan finds a PAN",
      Detect.scan "4111111111111111" = [ sp Detect.Pan 0 16 ] );
    ( "production scan finds an AWS key",
      Detect.scan "AKIAIOSFODNN7EXAMPLE" = [ sp Detect.Aws_key 0 20 ] );
    ( "production scan finds a Solana pubkey",
      Detect.scan "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
      = [ sp Detect.Sol_pubkey 0 43 ] );
    ( "production tree scrubs a PAN and leaves a short run",
      Detect.tree ~token:marker
        (Msgpack.Arr [ Msgpack.Str "1234"; Msgpack.Str "4111111111111111" ])
      = (Msgpack.Arr [ Msgpack.Str "1234"; Msgpack.Str "<pan>" ], [ sp Detect.Pan 0 16 ]) );
    ( "production record scrubs a PAN key and leaves a short value",
      Detect.record ~token:marker [ ("4111111111111111", Msgpack.Str "1234") ]
      = ([ ("<pan>", Msgpack.Str "1234") ], [ sp Detect.Pan 0 16 ]) );
    (* a matcher that ignores its input still resolves cleanly *)
    ( "a constant matcher is resolved like any other",
      Detect.scan_with [ const ~as_:Detect.Ssn [ (0, 4); (2, 6) ] ] "abcdefgh"
      = [ sp Detect.Ssn 0 4 ] );
    ( "scan_with drops negative, past-the-end and empty pairs against the scanned length",
      Detect.scan_with
        [ const ~as_:Detect.Ssn [ (-1, 2); (0, 4); (3, 3); (1, 3) ] ]
        "abc"
      = [ sp Detect.Ssn 1 3 ] );
  ]

let () =
  let failures =
    List.fold_left
      (fun n (name, ok) ->
        Printf.printf "%s %s\n" (if ok then "PASS" else "FAIL") name;
        if ok then n else n + 1)
      0 checks
  in
  match failures with
  | 0 -> print_endline "test_detect: PASS"
  | _ ->
    print_endline "test_detect: FAIL";
    exit 1
