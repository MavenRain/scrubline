(* M13: Luhn and the PAN detector.  Group A pins Luhn on the public
   issuer test numbers and on its two error-detection guarantees;
   groups B and C are the PAN corpus (separator forms fire;  Luhn-
   failing, embedded, and mis-separated runs stay);  group D drives
   the production surface, which carries Pan since M13;  group E is a
   deterministic sweep over generated numbers in random separator
   layouts.  Bare [Pan.find] pins are exact where the layout admits
   one window only;  [Detect.scan] pins cover the resolved result. *)

open Scrubline

let sp (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Pan; start = a; stop = b }

let is_digit (c : char) : bool = '0' <= c && c <= '9'

let digits (s : string) : int list =
  String.to_seq s
  |> Seq.filter is_digit
  |> Seq.map (fun (c : char) -> Char.code c - Char.code '0')
  |> List.of_seq

let luhn (s : string) : bool = Luhn.valid (digits s)

let marker : Detect.detector -> string -> string =
  fun d (_ : string) -> "<" ^ Detect.to_string d ^ ">"

let scrub (s : string) : string =
  Detect.replace ~token:marker s (Detect.scan s)

(* Public issuer test numbers, all Luhn-valid. *)
let visa16 : string = "4111111111111111"

let visa13 : string = "4222222222222"

let amex15 : string = "378282246310005"

let diners14 : string = "30569309025904"

let mc16 : string = "5555555555554444"

let discover16 : string = "6011111111111117"

let jcb16 : string = "3530111333300000"

(* Computed forms: 18 digits plus the check digit that closes them;
   a valid 12-digit and a valid 20-digit run for the length controls. *)
let union19 : string = "6221260000000000001"

let short12 : string = "411111111117"

let long20 : string = "41111111111111110000"

let fire_corpus : string list =
  [ visa16; visa13; amex15; diners14; mc16; discover16; jcb16; union19;
    "4111 1111 1111 1111"; "4111-1111-1111-1111"; "3782 822463 10005";
    "card 4111111111111111 exp 12/26"; "order-4111111111111111";
    visa16 ^ " " ^ mc16 ]

let count_true (bs : bool list) : int =
  List.fold_left (fun (n : int) (b : bool) -> if b then n + 1 else n) 0 bs

let digit_chars : char list = List.of_seq (String.to_seq "0123456789")

let chr_of_digit (d : int) : char =
  Option.value ~default:'0' (List.nth_opt digit_chars d)

(* Every single-digit substitution of [s]: does Luhn reject it? *)
let substitutions (s : string) : bool list =
  let cs = List.of_seq (String.to_seq s) in
  List.concat
    (List.mapi
       (fun (i : int) (orig : char) ->
         List.filter_map
           (fun (c : char) ->
             match () with
             | () when c = orig -> None
             | () ->
               let m =
                 List.mapi
                   (fun (j : int) (x : char) -> if j = i then c else x)
                   cs
               in
               Some (not (luhn (String.of_seq (List.to_seq m)))))
           digit_chars)
       cs)

let swapped (cs : char list) (i : int) : string =
  let a = Option.value ~default:' ' (List.nth_opt cs i) in
  let b = Option.value ~default:' ' (List.nth_opt cs (i + 1)) in
  List.mapi
    (fun (j : int) (x : char) ->
      match () with
      | () when j = i -> b
      | () when j = i + 1 -> a
      | () -> x)
    cs
  |> List.to_seq |> String.of_seq

(* Every adjacent transposition of two distinct digits: rejected? *)
let transpositions (s : string) : bool list =
  let cs = List.of_seq (String.to_seq s) in
  List.filter_map
    (fun (i : int) ->
      match () with
      | () when List.nth_opt cs i = List.nth_opt cs (i + 1) -> None
      | () -> Some (not (luhn (swapped cs i))))
    (List.init (max 0 (List.length cs - 1)) Fun.id)

(* Sweep support: the deterministic LCG from test_detect. *)
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

(* Lay the digits out with a random single separator in some gaps.
   The layout depends on the seed and the digit count only, so two
   digit lists of one length get the same separators. *)
let rec layout (seed : int) (ds : int list) (acc : char list) : int * string =
  match ds with
  | [] -> (seed, String.of_seq (List.to_seq (List.rev acc)))
  | d :: tl ->
    let seed = next seed in
    let gap =
      match () with
      | () when acc = [] -> []
      | () when (seed lsr 6) land 7 = 0 -> [ ' ' ]
      | () when (seed lsr 6) land 7 = 1 -> [ '-' ]
      | () -> []
    in
    layout seed tl (chr_of_digit d :: (gap @ acc))

type pcase = { text : string; broken : string }

(* A valid number in a random separator layout, and the same layout
   with its check digit bumped (Luhn catches every single-digit
   change), each embedded between two letters. *)
let rec gen_cases (seed : int) (n : int) (acc : pcase list) : pcase list =
  match () with
  | () when n <= 0 -> acc
  | () ->
    let seed = next seed in
    let len = 12 + rem_small ((seed lsr 4) land 7) 7 in
    let seed, body = gen_digits seed len [] in
    let c = check_digit body in
    let bumped =
      match () with
      | () when c = 9 -> 0
      | () -> c + 1
    in
    let seed', text = layout seed (body @ [ c ]) [] in
    let (_ : int), broken = layout seed (body @ [ bumped ]) [] in
    gen_cases seed' (n - 1)
      ({ text = "x" ^ text ^ "y"; broken = "x" ^ broken ^ "y" } :: acc)

let cases : pcase list = gen_cases 2024 200 []

let whole (s : string) : int * int = (1, String.length s - 1)

(* The full window is a candidate, and it is what resolution keeps. *)
let fires (p : pcase) : bool =
  List.mem (whole p.text) (Pan.find p.text)
  && Detect.scan p.text = [ sp 1 (String.length p.text - 1) ]

(* The full window is not a candidate once the check digit is off. *)
let stays (p : pcase) : bool = not (List.mem (whole p.broken) (Pan.find p.broken))

let has_sep (s : string) : bool = String.contains s ' ' || String.contains s '-'

(* The layout of a string: every digit reads as 'd' and the separators
   stay, so two strings share a layout when their shapes are equal. *)
let shape (s : string) : string =
  String.map
    (fun (c : char) ->
      match () with
      | () when is_digit c -> 'd'
      | () -> c)
    s

let checks : (string * bool) list =
  [ (* A. Luhn *)
    ("luhn: visa 16", luhn visa16);
    ("luhn: visa 13", luhn visa13);
    ("luhn: amex 15", luhn amex15);
    ("luhn: diners 14", luhn diners14);
    ("luhn: mastercard 16", luhn mc16);
    ("luhn: discover 16", luhn discover16);
    ("luhn: jcb 16", luhn jcb16);
    ("luhn: the computed 19", luhn union19);
    ("luhn: the reference example 79927398713", luhn "79927398713");
    ("luhn: 18 doubles the 1", luhn "18");
    ("luhn: a lone 0", luhn "0");
    ("luhn: the empty list is the empty sum", Luhn.valid []);
    ( "luhn: visa 16 with its check digit bumped fails",
      not (luhn "4111111111111112") );
    ( "luhn: a lone 10 fails closed where the raw sum would close",
      not (Luhn.valid [ 10 ]) );
    ( "luhn: a negative digit fails closed where the raw sum would close",
      not (Luhn.valid [ 1; -2 ]) );
    ( "luhn: 10 fails closed even where the raw sum would close",
      not (Luhn.valid [ 0; 10 ]) );
    ( "luhn: every single-digit substitution of visa 16 fails",
      count_true (substitutions visa16) = 144 );
    ( "luhn: every distinct adjacent transposition of 79927398713 fails",
      count_true (transpositions "79927398713") = 9 );
    (* B. PAN forms that fire *)
    ("pan: bare 16", Pan.find visa16 = [ (0, 16) ]);
    ("pan: bare 13", Pan.find visa13 = [ (0, 13) ]);
    ("pan: bare 14", Pan.find diners14 = [ (0, 14) ]);
    ("pan: bare 15", Pan.find amex15 = [ (0, 15) ]);
    ("pan: bare 19", Pan.find union19 = [ (0, 19) ]);
    ("pan: spaces 4-4-4-4", Pan.find "4111 1111 1111 1111" = [ (0, 19) ]);
    ("pan: dashes 4-4-4-4", Pan.find "4111-1111-1111-1111" = [ (0, 19) ]);
    ("pan: mixed separators", Pan.find "4111 1111-1111 1111" = [ (0, 19) ]);
    ("pan: amex 4-6-5", Pan.find "3782 822463 10005" = [ (0, 17) ]);
    ( "pan: one separator in every gap",
      Detect.scan "4-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1" = [ sp 0 31 ] );
    ( "pan: inside a sentence",
      Pan.find "card 4111111111111111 exp 12/26" = [ (5, 21) ] );
    ("pan: after a dash", Pan.find "order-4111111111111111" = [ (6, 22) ]);
    ( "pan: leading and trailing separators are outside the span",
      Pan.find " 4111111111111111-" = [ (1, 17) ] );
    ( "pan: a valid number after an unrelated short one is found",
      Pan.find "100 4111111111111111" = [ (4, 20) ] );
    ( "pan: the 100 prefix stays out because the merged 19 digits fail Luhn",
      not (luhn ("100" ^ visa16)) );
    ( "pan: two numbers in one string",
      Pan.find (visa16 ^ " " ^ mc16) = [ (0, 16); (17, 33) ] );
    ( "pan: two numbers joined by a dash",
      Pan.find (visa16 ^ "-" ^ mc16) = [ (0, 16); (17, 33) ] );
    (* C. controls that stay *)
    ("stay: empty string", Pan.find "" = []);
    ("stay: luhn-failing bare run", Pan.find "4111111111111112" = []);
    ("stay: luhn-failing separated run", Pan.find "4111 1111 1111 1112" = []);
    ("stay: 12 digits, luhn-valid", Pan.find short12 = []);
    ("stay: 20 digits, luhn-valid", Pan.find long20 = []);
    ("stay: a digit before the number", Pan.find ("9" ^ visa16) = []);
    ("stay: a digit after the number", Pan.find (visa16 ^ "2") = []);
    ( "stay: a digit after the separated form",
      Pan.find "4111 1111 1111 11114" = [] );
    ("stay: a double space", Pan.find "4111  1111 1111 1111" = []);
    ("stay: a double dash", Pan.find "4111--1111-1111-1111" = []);
    ("stay: dots are not separators", Pan.find "4111.1111.1111.1111" = []);
    ("stay: slashes are not separators", Pan.find "4111/1111/1111/1111" = []);
    ("stay: tabs are not separators", Pan.find "4111\t1111\t1111\t1111" = []);
    (* the documented residual: a wrapped number is two runs (DESIGN 5) *)
    ("stay: a newline is not a separator", Pan.find "4111 1111\n1111 1111" = []);
    ( "stay: fullwidth digits are not digits",
      Pan.find "\xef\xbc\x94\xef\xbc\x91\xef\xbc\x91\xef\xbc\x91" = [] );
    (* D. the production surface *)
    ("scan: visa 16 is a Pan span", Detect.scan visa16 = [ sp 0 16 ]);
    ( "scan: the resolved span after an unrelated short number",
      Detect.scan "100 4111111111111111" = [ sp 4 20 ] );
    (* the documented residual (DESIGN 5): one separator can merge an
       unrelated short run into the number, and about one prefix in ten
       closes the merged window under Luhn.  The merged leftmost span
       then wins and over-redacts the prefix, the safe side: it still
       consumes every card digit. *)
    ( "pan: merge control is non-vacuous, 109 ^ visa16 passes Luhn",
      luhn ("109" ^ visa16) );
    ( "pan: an unrelated prefix that closes Luhn merges into one window",
      Pan.find ("109 " ^ visa16) = [ (0, 20); (4, 20) ] );
    ( "pan: resolution keeps the merged leftmost span, the safe side",
      Detect.scan ("109 " ^ visa16) = [ sp 0 20 ] );
    ( "pan: the merged span consumes every card digit",
      scrub ("109 " ^ visa16) = "<pan>" );
    ( "scrub: a sentence",
      scrub "card 4111 1111 1111 1111 exp 12/26" = "card <pan> exp 12/26" );
    ("scrub: two numbers", scrub (visa16 ^ " " ^ mc16) = "<pan> <pan>");
    ( "scrub: a clean string is untouched",
      scrub "amount 100 at 12:26" = "amount 100 at 12:26" );
    ( "scrub: every fire-corpus entry fires",
      List.for_all (fun (s : string) -> Detect.scan s <> []) fire_corpus );
    ( "scrub: no fire-corpus entry fires again once scrubbed",
      List.for_all (fun (s : string) -> Detect.scan (scrub s) = []) fire_corpus );
    ( "tree: a PAN in a nested value is scrubbed",
      Detect.tree ~token:marker
        (Msgpack.Map [ (Msgpack.Str "pan", Msgpack.Arr [ Msgpack.Str visa16 ]) ])
      = ( Msgpack.Map [ (Msgpack.Str "pan", Msgpack.Arr [ Msgpack.Str "<pan>" ]) ],
          [ sp 0 16 ] ) );
    ( "record: a PAN in a field name is scrubbed",
      Detect.record ~token:marker [ (visa16, Msgpack.Str "x") ]
      = ([ ("<pan>", Msgpack.Str "x") ], [ sp 0 16 ]) );
    ( "record: a Bin payload is never scanned",
      (let r = [ ("b", Msgpack.Bin visa16) ] in
       Detect.record ~token:marker r = (r, [])) );
    (* E. sweep *)
    ("sweep: 200 cases generated", List.length cases = 200);
    ("sweep: every generated layout fires as one span", List.for_all fires cases);
    ("sweep: every check-digit bump stays", List.for_all stays cases);
    ( "sweep: every broken twin shares its layout",
      List.for_all
        (fun (p : pcase) -> shape p.text = shape p.broken)
        cases );
    ( "sweep: non-vacuous, separated layouts occur",
      List.exists (fun (p : pcase) -> has_sep p.text) cases );
    ( "sweep: non-vacuous, every digit count 13..19 occurs",
      List.for_all
        (fun (n : int) ->
          List.exists (fun (p : pcase) -> List.length (digits p.text) = n) cases)
        (List.init 7 (fun (i : int) -> 13 + i)) );
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
  | 0 -> print_endline "test_pan: PASS"
  | _ ->
    print_endline "test_pan: FAIL";
    exit 1
