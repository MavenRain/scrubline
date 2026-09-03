(* M14: the SSN detector.  Group A is the forms that fire and group B
   the controls that stay (the area, group and serial rules, digit-
   adjacent ends, mis-grouped and mis-separated runs);  group C sweeps
   every area, group and serial in both layouts;  group D drives the
   production surface, which carries Pan and Ssn at M14, including the
   overlap where a PAN contains an SSN-shaped window;  group E is a
   deterministic sweep over generated numbers in both layouts, each
   with a broken twin.  Bare [Ssn.find] pins are exact: every start
   yields at most one window, so the whole result is pinned. *)

open Scrubline

let sp (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Ssn; start = a; stop = b }

let sp_pan (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Pan; start = a; stop = b }

let is_digit (c : char) : bool = '0' <= c && c <= '9'

let digits (s : string) : int list =
  String.to_seq s
  |> Seq.filter is_digit
  |> Seq.map (fun (c : char) -> Char.code c - Char.code '0')
  |> List.of_seq

let marker : Detect.detector -> string -> string =
  fun d (_ : string) -> "<" ^ Detect.to_string d ^ ">"

let scrub (s : string) : string =
  Detect.replace ~token:marker s (Detect.scan s)

let count_true (bs : bool list) : int =
  List.fold_left (fun (n : int) (b : bool) -> if b then n + 1 else n) 0 bs

let digit_chars : char list = List.of_seq (String.to_seq "0123456789")

let chr_of_digit (d : int) : char =
  Option.value ~default:'0' (List.nth_opt digit_chars d)

(* One char as a string, so the sweeps need no arithmetic on ints. *)
let str1 (c : char) : string = String.make 1 c

(* Sweep support: the deterministic LCG from test_pan. *)
let next (seed : int) : int = (seed * 1103515245 + 12345) land 0x3fffffff

let rec rem_small (v : int) (m : int) : int =
  match () with
  | () when m <= 0 -> 0
  | () when v < m -> v
  | () -> rem_small (v - m) m

let rec gen_digits (seed : int) (n : int) (acc : int list) : int * int list =
  match () with
  | () when n <= 0 -> (seed, List.rev acc)
  | () ->
    let seed = next seed in
    gen_digits seed (n - 1) (rem_small ((seed lsr 8) land 15) 10 :: acc)

(* The one digit that closes [body] under Luhn. *)
let check_digit (body : int list) : int =
  Option.value ~default:0
    (List.find_opt
       (fun (c : int) -> Luhn.valid (body @ [ c ]))
       (List.init 10 Fun.id))

(* C. every part value, as chars, so the rules read off the digits. *)
let area_triples : (char * char * char) list =
  List.concat_map
    (fun (a : char) ->
      List.concat_map
        (fun (b : char) -> List.map (fun (c : char) -> (a, b, c)) digit_chars)
        digit_chars)
    digit_chars

let group_pairs : (char * char) list =
  List.concat_map
    (fun (a : char) -> List.map (fun (b : char) -> (a, b)) digit_chars)
    digit_chars

let serial_quads : (char * char * char * char) list =
  List.concat_map
    (fun (a : char) ->
      List.concat_map
        (fun (b : char) ->
          List.concat_map
            (fun (c : char) ->
              List.map (fun (d : char) -> (a, b, c, d)) digit_chars)
            digit_chars)
        digit_chars)
    digit_chars

let area_str (((a : char), (b : char), (c : char)) : char * char * char) :
    string =
  str1 a ^ str1 b ^ str1 c

let group_str (((a : char), (b : char)) : char * char) : string =
  str1 a ^ str1 b

let serial_str
    (((a : char), (b : char), (c : char), (d : char)) :
      char * char * char * char) : string =
  str1 a ^ str1 b ^ str1 c ^ str1 d

(* The area rule, stated again over the digits themselves. *)
let area_rule (((a : char), (b : char), (c : char)) : char * char * char) :
    bool =
  (not (a = '0' && b = '0' && c = '0'))
  && (not (a = '6' && b = '6' && c = '6'))
  && a <> '9'

let area_dashed (t : char * char * char) : string = area_str t ^ "-45-6789"

let area_bare (t : char * char * char) : string = area_str t ^ "456789"

let group_dashed (p : char * char) : string = "123-" ^ group_str p ^ "-6789"

let group_bare (p : char * char) : string = "123" ^ group_str p ^ "6789"

let serial_dashed (q : char * char * char * char) : string =
  "123-45-" ^ serial_str q

let serial_bare (q : char * char * char * char) : string =
  "12345" ^ serial_str q

(* D. a PAN that contains an SSN-shaped window.  The 17th digit is the
   one that closes the 16 digits of the layout under Luhn. *)
let overlap_text : string =
  "4111-123-45-6789-111"
  ^ str1 (chr_of_digit (check_digit (digits "4111123456789111")))

let fire_corpus : string list =
  [ "123-45-6789"; "123456789"; "ssn 123-45-6789 end"; "ssn=123456789;";
    "-123-45-6789-"; "a123456789b"; "123-45-6789-0";
    "123-45-6789 234-56-7890"; "123456789 234567890";
    "123-45-6789 234567890"; "001-01-0001"; "899-99-9999"; "665-45-6789";
    "667-45-6789"; "100-45-6789"; "078-05-1120"; "001010001"; "899999999" ]

(* E. nine LCG digits per case, fixed up until the rule holds.  Every
   fix-up is total and deterministic: the area first digit is capped
   below 9, then 000 and 666 are nudged;  a 00 group and an all-zero
   serial are nudged too. *)
let nth_digit (ds : int list) (i : int) : int =
  Option.value ~default:0 (List.nth_opt ds i)

let fix_area (a1 : int) (a2 : int) (a3 : int) : int * int * int =
  let a1 = rem_small a1 9 in
  match () with
  | () when a1 = 0 && a2 = 0 && a3 = 0 -> (a1, a2, 1)
  | () when a1 = 6 && a2 = 6 && a3 = 6 -> (a1, a2, 7)
  | () -> (a1, a2, a3)

let fix_group (g1 : int) (g2 : int) : int * int =
  match () with
  | () when g1 = 0 && g2 = 0 -> (g1, 1)
  | () -> (g1, g2)

let fix_serial (s1 : int) (s2 : int) (s3 : int) (s4 : int) :
    int * int * int * int =
  match () with
  | () when s1 = 0 && s2 = 0 && s3 = 0 && s4 = 0 -> (s1, s2, s3, 1)
  | () -> (s1, s2, s3, s4)

let digits2 (a : int) (b : int) : string =
  str1 (chr_of_digit a) ^ str1 (chr_of_digit b)

let digits3 (a : int) (b : int) (c : int) : string =
  digits2 a b ^ str1 (chr_of_digit c)

let digits4 (a : int) (b : int) (c : int) (d : int) : string =
  digits2 a b ^ digits2 c d

(* Dashed or bare, from the parts. *)
let render ~(dashed : bool) (a : string) (g : string) (s : string) : string =
  match () with
  | () when dashed -> a ^ "-" ^ g ^ "-" ^ s
  | () -> a ^ g ^ s

type scase =
  { text : string; broken : string; dashed : bool; broke : int; a1 : int }

(* The twin breaks one part, cycling over the five breakings by the
   case index, and keeps the layout. *)
let broken_parts (b : int) (a2 : int) (a3 : int) (area : string)
    (grp : string) (ser : string) : string * string * string =
  match () with
  | () when b = 0 -> ("000", grp, ser)
  | () when b = 1 -> ("666", grp, ser)
  | () when b = 2 -> (digits3 9 a2 a3, grp, ser)
  | () when b = 3 -> (area, "00", ser)
  | () -> (area, grp, "0000")

let rec gen_cases (seed : int) (k : int) (n : int) (acc : scase list) :
    scase list =
  match () with
  | () when n <= 0 -> acc
  | () ->
    let seed, ds = gen_digits seed 9 [] in
    let a1, a2, a3 =
      fix_area (nth_digit ds 0) (nth_digit ds 1) (nth_digit ds 2)
    in
    let g1, g2 = fix_group (nth_digit ds 3) (nth_digit ds 4) in
    let s1, s2, s3, s4 =
      fix_serial (nth_digit ds 5) (nth_digit ds 6) (nth_digit ds 7)
        (nth_digit ds 8)
    in
    let seed = next seed in
    let dashed = (seed lsr 6) land 1 = 0 in
    let area = digits3 a1 a2 a3 in
    let grp = digits2 g1 g2 in
    let ser = digits4 s1 s2 s3 s4 in
    let broke = rem_small k 5 in
    let ba, bg, bs = broken_parts broke a2 a3 area grp ser in
    gen_cases seed (k + 1) (n - 1)
      ({ text = "x" ^ render ~dashed area grp ser ^ "y";
         broken = "x" ^ render ~dashed ba bg bs ^ "y";
         dashed;
         broke;
         a1 }
      :: acc)

let cases : scase list = gen_cases 2024 0 200 []

let whole (s : string) : int * int = (1, String.length s - 1)

(* The embedded window is the only candidate, and it is what
   resolution keeps. *)
let fires (p : scase) : bool =
  Ssn.find p.text = [ whole p.text ]
  && Detect.scan p.text = [ sp 1 (String.length p.text - 1) ]

let stays (p : scase) : bool = Ssn.find p.broken = []

(* The layout of a string: every digit reads as 'd' and the dashes
   stay, so two strings share a layout when their shapes are equal. *)
let shape (s : string) : string =
  String.map
    (fun (c : char) ->
      match () with
      | () when is_digit c -> 'd'
      | () -> c)
    s

let checks : (string * bool) list =
  [ (* A. forms that fire *)
    ("ssn: the dashed form", Ssn.find "123-45-6789" = [ (0, 11) ]);
    ("ssn: the bare form", Ssn.find "123456789" = [ (0, 9) ]);
    ("ssn: inside a sentence", Ssn.find "ssn 123-45-6789 end" = [ (4, 15) ]);
    ("ssn: between punctuation", Ssn.find "ssn=123456789;" = [ (4, 13) ]);
    ("ssn: a dash is not a digit", Ssn.find "-123-45-6789-" = [ (1, 12) ]);
    ("ssn: letters are not digits", Ssn.find "a123456789b" = [ (1, 10) ]);
    ( "ssn: the successor byte is the dash",
      Ssn.find "123-45-6789-0" = [ (0, 11) ] );
    ( "ssn: two dashed numbers",
      Ssn.find "123-45-6789 234-56-7890" = [ (0, 11); (12, 23) ] );
    ( "ssn: two bare numbers",
      Ssn.find "123456789 234567890" = [ (0, 9); (10, 19) ] );
    ( "ssn: mixed forms",
      Ssn.find "123-45-6789 234567890" = [ (0, 11); (12, 21) ] );
    ( "ssn: area 001, group 01, serial 0001",
      Ssn.find "001-01-0001" = [ (0, 11) ] );
    ("ssn: area 899", Ssn.find "899-99-9999" = [ (0, 11) ]);
    ("ssn: area 665", Ssn.find "665-45-6789" = [ (0, 11) ]);
    ("ssn: area 667", Ssn.find "667-45-6789" = [ (0, 11) ]);
    ("ssn: area 100", Ssn.find "100-45-6789" = [ (0, 11) ]);
    (* the SSA never issued 078-05-1120;  a denylist is an M19 decision *)
    ( "ssn: a never-issued number still fires",
      Ssn.find "078-05-1120" = [ (0, 11) ] );
    ("ssn: bare area 001", Ssn.find "001010001" = [ (0, 9) ]);
    ("ssn: bare area 899", Ssn.find "899999999" = [ (0, 9) ]);
    (* B. controls that stay *)
    ("stay: area 000 dashed", Ssn.find "000-45-6789" = []);
    ("stay: area 000 bare", Ssn.find "000456789" = []);
    ("stay: area 666 dashed", Ssn.find "666-45-6789" = []);
    ("stay: area 666 bare", Ssn.find "666456789" = []);
    ("stay: area 900 dashed", Ssn.find "900-45-6789" = []);
    ("stay: area 900 bare", Ssn.find "900456789" = []);
    ("stay: area 999 dashed", Ssn.find "999-45-6789" = []);
    ("stay: area 999 bare", Ssn.find "999456789" = []);
    ("stay: area 950 dashed", Ssn.find "950-45-6789" = []);
    ("stay: group 00 dashed", Ssn.find "123-00-6789" = []);
    ("stay: group 00 bare", Ssn.find "123006789" = []);
    ("stay: serial 0000 dashed", Ssn.find "123-45-0000" = []);
    ("stay: serial 0000 bare", Ssn.find "123450000" = []);
    ("stay: a digit before the dashed form", Ssn.find "1123-45-6789" = []);
    ("stay: a digit after the dashed form", Ssn.find "123-45-67890" = []);
    ("stay: a digit before the bare form", Ssn.find "1123456789" = []);
    ("stay: a digit after the bare form", Ssn.find "1234567890" = []);
    ("stay: ten digits opening with a zero", Ssn.find "0123456789" = []);
    ("stay: eight digits", Ssn.find "12345678" = []);
    ("stay: eleven digits", Ssn.find "12345678901" = []);
    ("stay: grouped 3-3-3", Ssn.find "123-456-789" = []);
    ("stay: grouped 2-3-4", Ssn.find "12-345-6789" = []);
    ("stay: grouped 3-2-3-1", Ssn.find "123-45-678-9" = []);
    ("stay: grouped 6-3", Ssn.find "123456-789" = []);
    ("stay: grouped 3-6", Ssn.find "123-456789" = []);
    ("stay: grouped 5-4", Ssn.find "12345-6789" = []);
    ("stay: grouped 4-1-4", Ssn.find "1234-5-6789" = []);
    ("stay: grouped 3-2-2-2", Ssn.find "123-45-67-89" = []);
    ("stay: a double dash after the area", Ssn.find "123--45-6789" = []);
    ("stay: a double dash after the group", Ssn.find "123-45--6789" = []);
    (* the documented residual: the space form is held for M19 *)
    ("stay: spaces are not separators", Ssn.find "123 45 6789" = []);
    ("stay: dots are not separators", Ssn.find "123.45.6789" = []);
    ("stay: slashes are not separators", Ssn.find "123/45/6789" = []);
    ("stay: underscores are not separators", Ssn.find "123_45_6789" = []);
    ("stay: a space for the second dash", Ssn.find "123-45 6789" = []);
    ("stay: a newline for the second dash", Ssn.find "123-45\n6789" = []);
    ("stay: a newline after the second dash", Ssn.find "123-45-\n6789" = []);
    ( "stay: fullwidth digits in the area",
      Ssn.find "\xef\xbc\x91\xef\xbc\x92\xef\xbc\x93-45-6789" = [] );
    ( "stay: fullwidth digits in the serial",
      Ssn.find "123-45-\xef\xbc\x96\xef\xbc\x97\xef\xbc\x98\xef\xbc\x99" = [] );
    ("stay: a bare PAN is not an SSN", Ssn.find "4111111111111111" = []);
    ("stay: a spaced PAN is not an SSN", Ssn.find "4111 1111 1111 1111" = []);
    ("stay: a dashed PAN is not an SSN", Ssn.find "4111-1111-1111-1111" = []);
    ("stay: the empty string", Ssn.find "" = []);
    ("stay: a lone dash", Ssn.find "-" = []);
    ("stay: no serial", Ssn.find "123-45-" = []);
    ("stay: a three-digit serial", Ssn.find "123-45-678" = []);
    (* C. exhaustive part sweeps *)
    ( "sweep-area: 898 of the 1000 dashed areas fire",
      count_true
        (List.map
           (fun (t : char * char * char) ->
             Ssn.find (area_dashed t) = [ (0, 11) ])
           area_triples)
      = 898 );
    ( "sweep-area: every dashed area fires exactly under the rule",
      List.for_all
        (fun (t : char * char * char) ->
          (Ssn.find (area_dashed t) <> []) = area_rule t)
        area_triples );
    ( "sweep-area: 898 of the 1000 bare areas fire",
      count_true
        (List.map
           (fun (t : char * char * char) ->
             Ssn.find (area_bare t) = [ (0, 9) ])
           area_triples)
      = 898 );
    ( "sweep-area: every bare area fires exactly under the rule",
      List.for_all
        (fun (t : char * char * char) ->
          (Ssn.find (area_bare t) <> []) = area_rule t)
        area_triples );
    ( "sweep-group: 99 of the 100 dashed groups fire",
      count_true
        (List.map
           (fun (p : char * char) -> Ssn.find (group_dashed p) = [ (0, 11) ])
           group_pairs)
      = 99 );
    ( "sweep-group: 00 is the one dashed group that stays",
      List.filter
        (fun (p : char * char) -> Ssn.find (group_dashed p) = [])
        group_pairs
      = [ ('0', '0') ] );
    ( "sweep-group: 99 of the 100 bare groups fire",
      count_true
        (List.map
           (fun (p : char * char) -> Ssn.find (group_bare p) = [ (0, 9) ])
           group_pairs)
      = 99 );
    ( "sweep-group: 00 is the one bare group that stays",
      List.filter
        (fun (p : char * char) -> Ssn.find (group_bare p) = [])
        group_pairs
      = [ ('0', '0') ] );
    ( "sweep-serial: 9999 of the 10000 dashed serials fire",
      count_true
        (List.map
           (fun (q : char * char * char * char) ->
             Ssn.find (serial_dashed q) = [ (0, 11) ])
           serial_quads)
      = 9999 );
    ( "sweep-serial: 0000 is the one dashed serial that stays",
      List.filter
        (fun (q : char * char * char * char) ->
          Ssn.find (serial_dashed q) = [])
        serial_quads
      = [ ('0', '0', '0', '0') ] );
    ( "sweep-serial: 9999 of the 10000 bare serials fire",
      count_true
        (List.map
           (fun (q : char * char * char * char) ->
             Ssn.find (serial_bare q) = [ (0, 9) ])
           serial_quads)
      = 9999 );
    ( "sweep-serial: 0000 is the one bare serial that stays",
      List.filter
        (fun (q : char * char * char * char) -> Ssn.find (serial_bare q) = [])
        serial_quads
      = [ ('0', '0', '0', '0') ] );
    (* D. the production surface *)
    ( "scan: the dashed form is an Ssn span",
      Detect.scan "123-45-6789" = [ sp 0 11 ] );
    ( "scan: the bare form is an Ssn span",
      Detect.scan "123456789" = [ sp 0 9 ] );
    ("scrub: the dashed form", scrub "123-45-6789" = "<ssn>");
    ( "scrub: an SSN and a PAN in one sentence",
      scrub "ssn 123-45-6789 card 4111111111111111" = "ssn <ssn> card <pan>" );
    ( "scrub: a bare SSN then a PAN",
      scrub "123456789 4111111111111111" = "<ssn> <pan>" );
    ( "scan: a bare SSN then a PAN",
      Detect.scan "123456789 4111111111111111" = [ sp 0 9; sp_pan 10 26 ] );
    ( "scan: the overlap fixture is Luhn-valid",
      Luhn.valid (digits overlap_text) );
    ( "ssn: the window inside the overlap fixture is a candidate",
      Ssn.find overlap_text = [ (5, 16) ] );
    ( "scan: the whole overlap fixture is a PAN candidate",
      List.mem (0, 21) (Pan.find overlap_text) );
    ( "scan: the PAN starts first and takes the overlap",
      Detect.scan overlap_text = [ sp_pan 0 21 ] );
    ( "scan: an SSN right after a PAN",
      Detect.scan "4111111111111111 123-45-6789"
      = [ sp_pan 0 16; sp 17 28 ] );
    ( "tree: an SSN in a nested value is scrubbed",
      Detect.tree ~token:marker
        (Msgpack.Map
           [ (Msgpack.Str "ssn", Msgpack.Arr [ Msgpack.Str "123-45-6789" ]) ])
      = ( Msgpack.Map
            [ (Msgpack.Str "ssn", Msgpack.Arr [ Msgpack.Str "<ssn>" ]) ],
          [ sp 0 11 ] ) );
    ( "record: an SSN in a field name is scrubbed",
      Detect.record ~token:marker [ ("123456789", Msgpack.Str "x") ]
      = ([ ("<ssn>", Msgpack.Str "x") ], [ sp 0 9 ]) );
    ( "record: a Bin payload is never scanned",
      (let r = [ ("b", Msgpack.Bin "123-45-6789") ] in
       Detect.record ~token:marker r = (r, [])) );
    ( "scrub: every fire-corpus entry fires",
      List.for_all (fun (s : string) -> Detect.scan s <> []) fire_corpus );
    ( "scrub: no fire-corpus entry fires again once scrubbed",
      List.for_all (fun (s : string) -> Detect.scan (scrub s) = []) fire_corpus );
    (* E. sweep *)
    ("sweep: 200 cases generated", List.length cases = 200);
    ( "sweep: every generated window fires as one span",
      List.for_all fires cases );
    ("sweep: every broken twin stays", List.for_all stays cases);
    ( "sweep: every broken twin shares its layout",
      List.for_all
        (fun (p : scase) -> shape p.text = shape p.broken)
        cases );
    ( "sweep: non-vacuous, dashed layouts occur",
      List.exists (fun (p : scase) -> p.dashed) cases );
    ( "sweep: non-vacuous, bare layouts occur",
      List.exists (fun (p : scase) -> not p.dashed) cases );
    ( "sweep: non-vacuous, each of the five breakings occurs",
      List.for_all
        (fun (i : int) -> List.exists (fun (p : scase) -> p.broke = i) cases)
        (List.init 5 Fun.id) );
    ( "sweep: non-vacuous, an area starting with 0 occurs",
      List.exists (fun (p : scase) -> p.a1 = 0) cases );
    ( "sweep: non-vacuous, an area starting with 8 occurs",
      List.exists (fun (p : scase) -> p.a1 = 8) cases );
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
  | 0 -> print_endline "test_ssn: PASS"
  | _ ->
    print_endline "test_ssn: FAIL";
    exit 1
