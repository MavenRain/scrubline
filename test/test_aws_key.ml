(* M15: the AWS access-key-id detector.  Group A is the forms that fire
   and group B the controls that stay (the prefix without a tail, wrong
   tail lengths, a key byte at either end, case, the other AWS
   unique-id prefixes, fullwidth bytes, the secret access key);  group
   C sweeps all 256 byte values at the eight positions it names (the
   two neighbours, the four prefix bytes, the first tail byte and the
   last one) and every tail length 0..40.  Tail places 1..14 get no
   256-byte sweep;  the length sweep and group E cover them.  Group D
   drives the production surface, which carries Pan, Ssn and Aws_key
   at M15, including the overlaps where a key holds a PAN or an SSN in
   its tail;  group E is a deterministic sweep over generated keys in
   lowercase context, each with a broken twin.  Bare [Aws_key.find]
   pins are exact: every start yields at most one window, so the whole
   result is pinned. *)

open Scrubline

let sp (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Aws_key; start = a; stop = b }

let sp_pan (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Pan; start = a; stop = b }

let sp_ssn (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Ssn; start = a; stop = b }

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

(* The one digit that closes [body] under Luhn. *)
let check_digit (body : int list) : int =
  Option.value ~default:0
    (List.find_opt
       (fun (c : int) -> Luhn.valid (body @ [ c ]))
       (List.init 10 Fun.id))

(* Every byte value once;  [Bytesx.chr] is total. *)
let bytes : char list = List.init 256 Bytesx.chr

(* The AWS documentation example and its sixteen-byte tail. *)
let ex : string = "AKIAIOSFODNN7EXAMPLE"

let ex_tail : string = "IOSFODNN7EXAMPLE"

(* Fullwidth A, 1 and 7: three bytes each, none of them a key byte. *)
let fw_a : string = "\xef\xbc\xa1"

let fw_one : string = "\xef\xbc\x91"

let fw_seven : string = "\xef\xbc\x97"

(* C. one string per byte value, at each position the rule constrains. *)
let after (b : char) : string = ex ^ str1 b

let before (b : char) : string = str1 b ^ ex

let last_tail (b : char) : string = "AKIAIOSFODNN7EXAMPL" ^ str1 b

let first_tail (b : char) : string = "AKIA" ^ str1 b ^ "OSFODNN7EXAMPLE"

let pre1 (b : char) : string = str1 b ^ "KIA" ^ ex_tail

let pre2 (b : char) : string = "A" ^ str1 b ^ "IA" ^ ex_tail

let pre3 (b : char) : string = "AK" ^ str1 b ^ "A" ^ ex_tail

let pre4 (b : char) : string = "AKI" ^ str1 b ^ ex_tail

(* How many of the 256 bytes leave exactly the window [w]. *)
let sweep_count (f : char -> string) (w : int * int) : int =
  count_true (List.map (fun (b : char) -> Aws_key.find (f b) = [ w ]) bytes)

(* Which bytes fire, stated again as a predicate over the byte. *)
let sweep_rule (f : char -> string) (p : char -> bool) : bool =
  List.for_all (fun (b : char) -> (Aws_key.find (f b) <> []) = p b) bytes

let lens : int list = List.init 41 Fun.id

let len_text (p : string) (c : char) (n : int) : string = p ^ String.make n c

let len_count (p : string) (c : char) : int =
  count_true
    (List.map
       (fun (n : int) -> Aws_key.find (len_text p c n) = [ (0, 20) ])
       lens)

let len_rule (p : string) (c : char) : bool =
  List.for_all
    (fun (n : int) -> (Aws_key.find (len_text p c n) <> []) = (n = 16))
    lens

(* D. a key whose tail is a Luhn-valid PAN, one whose tail holds an
   SSN, and the three glued neighbours. *)
let t1 : string = "AKIA4111111111111111"

let t2 : string = "AKIA123456789EXAMPLE"

let t3 : string = "4111111111111111" ^ ex

let t4 : string = "123-45-6789" ^ ex

let t5 : string = ex ^ "123-45-6789"

(* An SSN whose first three digits are the last three tail bytes, so
   the candidate starts inside the window and ends past it. *)
let t6 : string = "AKIAABCDEFGHIJKLX123-45-6789"

let has_key (s : string) : bool =
  List.exists
    (fun (x : Detect.span) -> x.Detect.detector = Detect.Aws_key)
    (Detect.scan s)

let fire_corpus : string list =
  [ ex; "ASIA" ^ ex_tail; "AKIAI44QH8DHBEXAMPLE";
    "aws_access_key_id = " ^ ex; "\"" ^ ex ^ "\""; "x" ^ ex ^ "x";
    "-" ^ ex ^ "-"; ex ^ "="; ex ^ "\n"; ex ^ "/";
    "https://x?AWSAccessKeyId=" ^ ex ^ "&Signature=abc"; ex ^ " " ^ ex;
    ex ^ "," ^ "ASIA" ^ ex_tail; ex ^ "/" ^ ex;
    "AKIAAAAAAAAAAAAAAAAA"; "AKIAZZZZZZZZZZZZZZZZ";
    "AKIA0000000000000000"; "AKIA9999999999999999";
    "AKIA0189018901890189"; t1; fw_one ^ ex ]

(* E. the 36 key bytes, one tail byte per LCG step. *)
let key_chars : char list =
  List.of_seq (String.to_seq "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

(* The window alphabet, written out from the DESIGN rule [A-Z0-9] and
   not read back from Aws_key, so a sweep over it can refute a wrong
   alphabet instead of restating it. *)
let key_byte (b : char) : bool = List.mem b key_chars

let key_char (seed : int) : char =
  Option.value ~default:'A'
    (List.nth_opt key_chars (rem_small ((seed lsr 8) land 63) 36))

let rec gen_tail (seed : int) (n : int) (acc : char list) : int * char list =
  match () with
  | () when n <= 0 -> (seed, List.rev acc)
  | () ->
    let seed = next seed in
    gen_tail seed (n - 1) (key_char seed :: acc)

let str_of_chars (cs : char list) : string = String.of_seq (List.to_seq cs)

let head_char (cs : char list) : char =
  Option.value ~default:'A' (List.nth_opt cs 0)

let prefix_of (akia : bool) : string =
  match () with
  | () when akia -> "AKIA"
  | () -> "ASIA"

(* The accepted prefix with its last byte replaced by 'B': AKIA reads
   AKIB and ASIA reads ASIB.  One byte away from the prefix the case
   uses, so the twin follows the case instead of a fixed literal. *)
let wrong_prefix (p : string) : string =
  let n : int = String.length p in
  str_of_chars
    (List.mapi
       (fun (i : int) (c : char) ->
         match () with
         | () when i = n - 1 -> 'B'
         | () -> c)
       (List.of_seq (String.to_seq p)))

(* The lowercase context pins the adjacency decision on every case. *)
let wrap (left : string) (w : string) : string = left ^ w ^ "y"

(* One tail byte replaced by a lowercase letter. *)
let lower_at (p : int) (cs : char list) : char list =
  List.mapi
    (fun (i : int) (c : char) ->
      match () with
      | () when i = p -> 'a'
      | () -> c)
    cs

let drop_last (cs : char list) : char list =
  List.filteri (fun (i : int) (_ : char) -> i < 15) cs

(* The twin breaks one thing, cycling over the five breakings by the
   case index, and keeps the layout. *)
let broken_of (k : int) (b : int) (p : string) (tl : char list) : string =
  match () with
  | () when b = 0 ->
    wrap "x" (p ^ str_of_chars (lower_at (rem_small k 16) tl))
  | () when b = 1 -> wrap "x" (p ^ str_of_chars (drop_last tl))
  | () when b = 2 -> wrap "x" (p ^ str_of_chars tl ^ "Z")
  | () when b = 3 -> wrap "x" (wrong_prefix p ^ str_of_chars tl)
  | () -> wrap "7" (p ^ str_of_chars tl)

type kcase =
  { text : string; broken : string; akia : bool; broke : int; first : char }

let rec gen_cases (seed : int) (k : int) (n : int) (acc : kcase list) :
    kcase list =
  match () with
  | () when n <= 0 -> acc
  | () ->
    let seed, tl = gen_tail seed 16 [] in
    let seed = next seed in
    let akia = (seed lsr 6) land 1 = 0 in
    let p = prefix_of akia in
    let broke = rem_small k 5 in
    gen_cases seed (k + 1) (n - 1)
      ({ text = wrap "x" (p ^ str_of_chars tl);
         broken = broken_of k broke p tl;
         akia;
         broke;
         first = head_char tl }
      :: acc)

let cases : kcase list = gen_cases 2024 0 200 []

(* The embedded window is the only candidate.  A generated tail holds
   no PAN and no SSN: the longest digit run over the 200 texts is four,
   and an SSN needs nine digits.  So this pins the window, not
   resolution.  The overlap cases are t1 and t2 in group D. *)
let fires (p : kcase) : bool =
  Aws_key.find p.text = [ (1, 21) ] && Detect.scan p.text = [ sp 1 21 ]

(* The twin is never a key.  For the reason above it reads as no PAN
   and no SSN either. *)
let stays (p : kcase) : bool =
  Aws_key.find p.broken = [] && not (has_key p.broken)

let is_lower (c : char) : bool = 'a' <= c && c <= 'z'

(* A lowercase byte inside the key, positions 1..20, so the x and y
   wrapper bytes cannot satisfy the breaking-0 predicate. *)
let inner_lower (s : string) : bool =
  List.exists is_lower
    (List.filteri
       (fun (i : int) (_ : char) -> 0 < i && i < 21)
       (List.of_seq (String.to_seq s)))

(* What the twin text itself must show for each breaking.  This
   reads the produced string, not the recorded index. *)
let shows_breaking (i : int) (p : kcase) : bool =
  match () with
  | () when i = 0 -> String.length p.broken = 22 && inner_lower p.broken
  | () when i = 1 -> String.length p.broken = 21
  | () when i = 2 ->
    String.length p.broken = 23
    && String.ends_with ~suffix:"Zy" p.broken
  | () when i = 3 && p.akia -> String.starts_with ~prefix:"xAKIB" p.broken
  | () when i = 3 -> String.starts_with ~prefix:"xASIB" p.broken
  | () ->
    String.length p.broken = 22
    && String.starts_with ~prefix:"7A" p.broken

let checks : (string * bool) list =
  [ (* A. forms that fire *)
    ("key: the documentation example", Aws_key.find ex = [ (0, 20) ]);
    ("key: the ASIA prefix", Aws_key.find ("ASIA" ^ ex_tail) = [ (0, 20) ]);
    ( "key: the second documentation example",
      Aws_key.find "AKIAI44QH8DHBEXAMPLE" = [ (0, 20) ] );
    ( "key: after a config assignment",
      Aws_key.find ("aws_access_key_id = " ^ ex) = [ (20, 40) ] );
    ( "key: quotes are not key bytes",
      Aws_key.find ("\"" ^ ex ^ "\"") = [ (1, 21) ] );
    ( "key: lowercase letters are not key bytes",
      Aws_key.find ("x" ^ ex ^ "x") = [ (1, 21) ] );
    ( "key: dashes are not key bytes",
      Aws_key.find ("-" ^ ex ^ "-") = [ (1, 21) ] );
    ("key: an equals sign after", Aws_key.find (ex ^ "=") = [ (0, 20) ]);
    ("key: a newline after", Aws_key.find (ex ^ "\n") = [ (0, 20) ]);
    ("key: a slash after", Aws_key.find (ex ^ "/") = [ (0, 20) ]);
    ( "key: in a query string",
      Aws_key.find ("https://x?AWSAccessKeyId=" ^ ex ^ "&Signature=abc")
      = [ (25, 45) ] );
    ( "key: two keys split by a space",
      Aws_key.find (ex ^ " " ^ ex) = [ (0, 20); (21, 41) ] );
    ( "key: two keys split by a comma",
      Aws_key.find (ex ^ "," ^ "ASIA" ^ ex_tail) = [ (0, 20); (21, 41) ] );
    ( "key: two keys split by a slash",
      Aws_key.find (ex ^ "/" ^ ex) = [ (0, 20); (21, 41) ] );
    ( "key: a tail of sixteen A",
      Aws_key.find "AKIAAAAAAAAAAAAAAAAA" = [ (0, 20) ] );
    ( "key: a tail of sixteen Z",
      Aws_key.find "AKIAZZZZZZZZZZZZZZZZ" = [ (0, 20) ] );
    ( "key: a tail of sixteen 0",
      Aws_key.find "AKIA0000000000000000" = [ (0, 20) ] );
    ( "key: a tail of sixteen 9",
      Aws_key.find "AKIA9999999999999999" = [ (0, 20) ] );
    ( "key: a tail outside the base32 alphabet",
      Aws_key.find "AKIA0189018901890189" = [ (0, 20) ] );
    ("key: a tail that is a PAN", Aws_key.find t1 = [ (0, 20) ]);
    ( "key: a fullwidth digit before is three non-key bytes",
      Aws_key.find (fw_one ^ ex) = [ (3, 23) ] );
    (* B. controls that stay *)
    ("stay: the AKIA prefix alone", Aws_key.find "AKIA" = []);
    ("stay: the ASIA prefix alone", Aws_key.find "ASIA" = []);
    ("stay: a space after the prefix", Aws_key.find ("AKIA " ^ ex_tail) = []);
    ("stay: a dash after the prefix", Aws_key.find ("AKIA-" ^ ex_tail) = []);
    ( "stay: a dash inside the tail",
      Aws_key.find "AKIAIOSFODNN-7EXAMPLE" = [] );
    ( "stay: a fifteen-byte tail",
      Aws_key.find ("AKIA" ^ "IOSFODNN7EXAMPL") = [] );
    ("stay: a digit after the tail", Aws_key.find (ex ^ "1") = []);
    ("stay: a letter after the tail", Aws_key.find (ex ^ "A") = []);
    ("stay: two keys glued", Aws_key.find (ex ^ ex) = []);
    ("stay: a digit before the prefix", Aws_key.find ("1" ^ ex) = []);
    ("stay: an A before the prefix", Aws_key.find ("A" ^ ex) = []);
    ("stay: a Z before the prefix", Aws_key.find ("Z" ^ ex) = []);
    ("stay: a lowercase tail", Aws_key.find "AKIAiosfodnn7example" = []);
    ("stay: a lowercase prefix", Aws_key.find "akiaIOSFODNN7EXAMPLE" = []);
    ("stay: a mixed-case prefix", Aws_key.find ("Akia" ^ ex_tail) = []);
    ("stay: the prefix AKIB", Aws_key.find ("AKIB" ^ ex_tail) = []);
    ("stay: the prefix AKAI", Aws_key.find ("AKAI" ^ ex_tail) = []);
    ("stay: the prefix AGPA", Aws_key.find ("AGPA" ^ ex_tail) = []);
    ("stay: the prefix AIDA", Aws_key.find ("AIDA" ^ ex_tail) = []);
    ("stay: the prefix AROA", Aws_key.find ("AROA" ^ ex_tail) = []);
    ("stay: the prefix ASCA", Aws_key.find ("ASCA" ^ ex_tail) = []);
    ("stay: the prefix ANPA", Aws_key.find ("ANPA" ^ ex_tail) = []);
    ( "stay: the prefix shifted one byte",
      Aws_key.find ("KIA" ^ ex_tail ^ "A") = [] );
    ( "stay: a fullwidth A opens nothing",
      Aws_key.find (fw_a ^ "KIAIOSFODNN7EXAMPLE") = [] );
    ( "stay: a fullwidth digit inside the tail",
      Aws_key.find ("AKIAIOSFODNN" ^ fw_seven ^ "EXAMPLE") = [] );
    ( "stay: the 40-char secret access key",
      Aws_key.find "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" = [] );
    ("stay: a PAN is not a key", Aws_key.find "4111111111111111" = []);
    ("stay: an SSN is not a key", Aws_key.find "123-45-6789" = []);
    ("stay: the empty string", Aws_key.find "" = []);
    ("stay: one byte", Aws_key.find "A" = []);
    ("stay: two bytes", Aws_key.find "AK" = []);
    ("stay: three bytes", Aws_key.find "AKI" = []);
    (* C. exhaustive byte sweeps *)
    ( "sweep-byte: the test alphabet ties to the detector's",
      List.for_all
        (fun (b : char) -> key_byte b = Aws_key.is_key_char b)
        bytes );
    ( "sweep-byte: 220 successor bytes leave the window",
      sweep_count after (0, 20) = 220 );
    ( "sweep-byte: a successor closes the window exactly on the alphabet",
      sweep_rule after (fun (b : char) -> not (key_byte b)) );
    ( "sweep-byte: 220 predecessor bytes leave the window",
      sweep_count before (1, 21) = 220 );
    ( "sweep-byte: a predecessor closes the window exactly on the alphabet",
      sweep_rule before (fun (b : char) -> not (key_byte b)) );
    ( "sweep-byte: 36 last tail bytes fire",
      sweep_count last_tail (0, 20) = 36 );
    ( "sweep-byte: the last tail byte fires exactly on the alphabet",
      sweep_rule last_tail key_byte );
    ( "sweep-byte: 36 first tail bytes fire",
      sweep_count first_tail (0, 20) = 36 );
    ( "sweep-byte: the first tail byte fires exactly on the alphabet",
      sweep_rule first_tail key_byte );
    ("sweep-byte: 1 first prefix byte fires", sweep_count pre1 (0, 20) = 1);
    ( "sweep-byte: only A opens the prefix",
      sweep_rule pre1 (fun (b : char) -> b = 'A') );
    ("sweep-byte: 2 second prefix bytes fire", sweep_count pre2 (0, 20) = 2);
    ( "sweep-byte: only K and S follow the first A",
      sweep_rule pre2 (fun (b : char) -> b = 'K' || b = 'S') );
    ("sweep-byte: 1 third prefix byte fires", sweep_count pre3 (0, 20) = 1);
    ( "sweep-byte: only I holds the third prefix place",
      sweep_rule pre3 (fun (b : char) -> b = 'I') );
    ("sweep-byte: 1 fourth prefix byte fires", sweep_count pre4 (0, 20) = 1);
    ( "sweep-byte: only A closes the prefix",
      sweep_rule pre4 (fun (b : char) -> b = 'A') );
    (* C. the tail length *)
    ( "sweep-len: 1 of the 41 AKIA X tails fires",
      len_count "AKIA" 'X' = 1 );
    ( "sweep-len: an AKIA X tail fires exactly at sixteen",
      len_rule "AKIA" 'X' );
    ( "sweep-len: 1 of the 41 ASIA X tails fires",
      len_count "ASIA" 'X' = 1 );
    ( "sweep-len: an ASIA X tail fires exactly at sixteen",
      len_rule "ASIA" 'X' );
    ( "sweep-len: 1 of the 41 AKIA 7 tails fires",
      len_count "AKIA" '7' = 1 );
    ( "sweep-len: an AKIA 7 tail fires exactly at sixteen",
      len_rule "AKIA" '7' );
    ( "sweep-len: 1 of the 41 ASIA 7 tails fires",
      len_count "ASIA" '7' = 1 );
    ( "sweep-len: an ASIA 7 tail fires exactly at sixteen",
      len_rule "ASIA" '7' );
    (* D. the production surface *)
    ("scan: a key is an Aws_key span", Detect.scan ex = [ sp 0 20 ]);
    ("scrub: a key", scrub ex = "<aws_key>");
    ( "scrub: a key, a PAN and an SSN in one sentence",
      scrub "key AKIAIOSFODNN7EXAMPLE card 4111111111111111 ssn 123-45-6789"
      = "key <aws_key> card <pan> ssn <ssn>" );
    ("scan: the PAN tail fixture is Luhn-valid", Luhn.valid (digits t1));
    ( "scan: the PAN tail fixture ends on its check digit",
      chr_of_digit (check_digit (digits "411111111111111")) = '1' );
    ("scan: the PAN tail window is a candidate", Pan.find t1 = [ (4, 20) ]);
    ("key: a PAN tail is still a key", Aws_key.find t1 = [ (0, 20) ]);
    ( "scan: the key starts first and takes the PAN tail",
      Detect.scan t1 = [ sp 0 20 ] );
    ("scrub: a key whose tail is a PAN", scrub t1 = "<aws_key>");
    ("scan: the SSN tail window is a candidate", Ssn.find t2 = [ (4, 13) ]);
    ( "scan: the key starts first and takes the SSN tail",
      Detect.scan t2 = [ sp 0 20 ] );
    ("scan: a PAN glued before a key", Pan.find t3 = [ (0, 16) ]);
    ("stay: a key right after a digit", Aws_key.find t3 = []);
    ("scan: the glued PAN is the only span", Detect.scan t3 = [ sp_pan 0 16 ]);
    ( "scan: a PAN, a space, then a key",
      Detect.scan ("4111111111111111 " ^ ex) = [ sp_pan 0 16; sp 17 37 ] );
    ("scan: an SSN glued before a key", Ssn.find t4 = [ (0, 11) ]);
    ("stay: a key right after an SSN", Aws_key.find t4 = []);
    ("scan: the glued SSN is the only span", Detect.scan t4 = [ sp_ssn 0 11 ]);
    ("stay: a key right before an SSN", Aws_key.find t5 = []);
    ("scan: an SSN glued after a key", Ssn.find t5 = [ (20, 31) ]);
    ( "scan: the trailing SSN is the only span",
      Detect.scan t5 = [ sp_ssn 20 31 ] );
    ("key: a straddling SSN leaves the window", Aws_key.find t6 = [ (0, 20) ]);
    ( "scan: the straddling SSN is a candidate",
      Ssn.find t6 = [ (17, 28) ] );
    ( "scan: leftmost drops the straddler whole",
      Detect.scan t6 = [ sp 0 20 ] );
    ( "tree: a key in a nested value is scrubbed",
      Detect.tree ~token:marker
        (Msgpack.Map [ (Msgpack.Str "key", Msgpack.Arr [ Msgpack.Str ex ]) ])
      = ( Msgpack.Map
            [ (Msgpack.Str "key", Msgpack.Arr [ Msgpack.Str "<aws_key>" ]) ],
          [ sp 0 20 ] ) );
    ( "record: a key in a field name is scrubbed",
      Detect.record ~token:marker [ (ex, Msgpack.Str "x") ]
      = ([ ("<aws_key>", Msgpack.Str "x") ], [ sp 0 20 ]) );
    ( "record: a Bin payload is never scanned",
      (let r = [ ("b", Msgpack.Bin ex) ] in
       Detect.record ~token:marker r = (r, [])) );
    ( "scrub: every fire-corpus entry fires as a key",
      List.for_all has_key fire_corpus );
    ( "scrub: no fire-corpus entry is a key once scrubbed",
      List.for_all (fun (s : string) -> not (has_key (scrub s))) fire_corpus );
    (* E. sweep *)
    ("sweep: 200 cases generated", List.length cases = 200);
    ( "sweep: every generated key fires as one span",
      List.for_all fires cases );
    ("sweep: every broken twin stays", List.for_all stays cases);
    ( "sweep: non-vacuous, AKIA keys occur",
      List.exists (fun (p : kcase) -> p.akia) cases );
    ( "sweep: non-vacuous, ASIA keys occur",
      List.exists (fun (p : kcase) -> not p.akia) cases );
    ( "sweep: non-vacuous, each of the five breakings shows in a twin",
      List.for_all
        (fun (i : int) ->
          List.exists
            (fun (p : kcase) -> p.broke = i && shows_breaking i p)
            cases)
        (List.init 5 Fun.id) );
    ( "sweep: every twin shows the breaking recorded for it",
      List.for_all (fun (p : kcase) -> shows_breaking p.broke p) cases );
    ( "sweep: every twin differs from its text",
      List.for_all (fun (p : kcase) -> p.broken <> p.text) cases );
    ( "sweep: non-vacuous, each breaking occurs with both prefixes",
      List.for_all
        (fun (i : int) ->
          List.exists (fun (p : kcase) -> p.broke = i && p.akia) cases
          && List.exists
               (fun (p : kcase) -> p.broke = i && not p.akia)
               cases)
        (List.init 5 Fun.id) );
    ( "sweep: non-vacuous, a tail starting with a digit occurs",
      List.exists (fun (p : kcase) -> is_digit p.first) cases );
    ( "sweep: non-vacuous, a tail starting with a letter occurs",
      List.exists (fun (p : kcase) -> not (is_digit p.first)) cases );
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
  | 0 -> print_endline "test_aws_key: PASS"
  | _ ->
    print_endline "test_aws_key: FAIL";
    exit 1
