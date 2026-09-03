(* M17: the Ethereum address detector.  Group A is the forms that fire
   (five real addresses, the lowercase and the uppercase-hex form of
   one, and the contexts they turn up in) and group B the controls
   that stay (a short or a long hex run, an uppercase X, a missing
   prefix byte, a non-hex byte inside, an alphanumeric byte glued to
   either end, two addresses back to back);  group C sweeps all 256
   byte values at the seven positions the rule constrains, for three
   addresses;  group D drives the production surface, which carries
   Pan, Ssn, Aws_key, Sol_pubkey and Eth_address at M17, including the
   overlaps where an address holds a PAN or an SSN and the ones where
   an AWS key or a base58 key takes the bytes;  group E is a
   deterministic sweep over generated addresses in context, each with
   a broken twin.  Bare [Eth_address.find] pins are exact: every start
   yields at most one window, so the whole result is pinned. *)

open Scrubline

let sp (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Eth_address; start = a; stop = b }

let sp_pan (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Pan; start = a; stop = b }

let sp_ssn (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Ssn; start = a; stop = b }

let sp_aws (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Aws_key; start = a; stop = b }

let sp_sol (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Sol_pubkey; start = a; stop = b }

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

(* One char as a string, so the sweeps need no arithmetic on ints. *)
let str1 (c : char) : string = String.make 1 c

(* Sweep support: the deterministic LCG from test_pan. *)
let next (seed : int) : int = (seed * 1103515245 + 12345) land 0x3fffffff

let rec rem_small (v : int) (m : int) : int =
  match () with
  | () when m <= 0 -> 0
  | () when v < m -> v
  | () -> rem_small (v - m) m

let str_of_chars (cs : char list) : string = String.of_seq (List.to_seq cs)

(* Every byte value once;  [Bytesx.chr] is total. *)
let bytes : char list = List.init 256 Bytesx.chr

let chars (s : string) : char list = List.of_seq (String.to_seq s)

(* The first [n] bytes, and the bytes after them;  total on any [n]. *)
let take (n : int) (s : string) : string =
  str_of_chars (List.filteri (fun (i : int) (_ : char) -> i < n) (chars s))

let drop (n : int) (s : string) : string =
  str_of_chars (List.filteri (fun (i : int) (_ : char) -> i >= n) (chars s))

let has_addr (s : string) : bool =
  List.exists
    (fun (x : Detect.span) -> x.Detect.detector = Detect.Eth_address)
    (Detect.scan s)

(* The adjacency class and the hex bytes, stated again test side.  The
   sweeps never call the lib predicates;  a tie check pins them equal. *)
let t_alnum (c : char) : bool =
  ('0' <= c && c <= '9') || ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z')

let t_hex (c : char) : bool =
  ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')

(* Five addresses, 42 bytes each: the zero address, WETH, USDC, a
   well-known account, and the all-f one. *)
let zero : string = "0x0000000000000000000000000000000000000000"

let weth : string = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"

let usdc : string = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

let vitalik : string = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

let ff : string = "0xffffffffffffffffffffffffffffffffffffffff"

let weth_lower : string = String.lowercase_ascii weth

let weth_upper : string = "0x" ^ String.uppercase_ascii (drop 2 weth)

(* The SPL token program id, 43 bytes;  a PAN;  an AWS key id. *)
let token : string = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

let visa : string = "4111111111111111"

let ex : string = "AKIAIOSFODNN7EXAMPLE"

(* An e acute: two bytes, neither of them alphanumeric. *)
let e_acute : string = "\xc3\xa9"

(* A fullwidth 0: three bytes, none of them a hex byte. *)
let fw_zero : string = "\xef\xbc\x90"

(* A. the four things a bare address must do. *)
let addr_length (a : string) : bool = String.length a = 42

let addr_find (a : string) : bool = Eth_address.find a = [ (0, 42) ]

let addr_scan (a : string) : bool = Detect.scan a = [ sp 0 42 ]

let addr_scrub (a : string) : bool = scrub a = "<eth_address>"

(* B. a control leaves no window and no production span. *)
let stays (s : string) : bool =
  Eth_address.find s = [] && not (has_addr s)

(* C. one string per byte value, at each position the rule constrains. *)
let successor (a : string) (b : char) : string = a ^ str1 b

let predecessor (a : string) (b : char) : string = str1 b ^ a

let at0 (a : string) (b : char) : string = str1 b ^ drop 1 a

let at1 (a : string) (b : char) : string =
  take 1 a ^ str1 b ^ drop 2 a

let at2 (a : string) (b : char) : string =
  take 2 a ^ str1 b ^ drop 3 a

let at21 (a : string) (b : char) : string =
  take 21 a ^ str1 b ^ drop 22 a

let at41 (a : string) (b : char) : string = take 41 a ^ str1 b

(* How many of the 256 bytes leave exactly the span [w]. *)
let sweep_count (f : char -> string) (w : int * int) : int =
  count_true
    (List.map (fun (b : char) -> Eth_address.find (f b) = [ w ]) bytes)

(* Which bytes leave that span, stated again as a predicate. *)
let sweep_rule (f : char -> string) (w : int * int) (p : char -> bool) : bool =
  List.for_all
    (fun (b : char) -> (Eth_address.find (f b) = [ w ]) = p b)
    bytes

let not_alnum (b : char) : bool = not (t_alnum b)

let is_zero (b : char) : bool = b = '0'

let is_x (b : char) : bool = b = 'x'

(* D. an address whose hex holds a PAN, one whose hex holds an SSN,
   and the neighbours that take the bytes or give them up. *)
let t1 : string = "0xa4111111111111111bcdefabcdefabcdefabcdef"

let t2 : string = "0xa123456789bcdefabcdefabcdefabcdefabcdefa"

let t4 : string = "123" ^ weth

let t5 : string = "AKIAIOSFODNN7EXAMPL" ^ weth

let t6 : string = visa ^ " " ^ weth

let t7 : string = weth ^ " 123-45-6789"

let t8 : string = token ^ zero

let t9 : string = zero ^ token

let t10 : string = ex ^ " " ^ weth

(* E. the deterministic sweep.  Forty hex bytes, a context and a
   breaking, all drawn from one LCG walk. *)
let hex_chars : char list = chars "0123456789abcdefABCDEF"

(* Bits 8 to 23 of the seed.  The low bits of an LCG cycle too fast,
   and a full 30-bit draw would make [rem_small] walk too far. *)
let draw (seed : int) : int = (seed lsr 8) land 0xffff

let hex_of (v : int) : char =
  Option.value ~default:'0' (List.nth_opt hex_chars (rem_small (v lsr 8) 22))

(* One hex byte per LCG step, in generation order. *)
let rec gen_hex (seed : int) (n : int) (acc : char list) : int * char list =
  match () with
  | () when n <= 0 -> (seed, List.rev acc)
  | () ->
    let seed : int = next seed in
    gen_hex seed (n - 1) (hex_of (draw seed) :: acc)

type pcase = { text : string; broken : string; off : int; ctx : int;
               broke : int }

(* The five contexts, and the byte offset each puts the address at. *)
let in_context (c : int) (a : string) : string =
  match () with
  | () when c = 1 -> "\"" ^ a ^ "\""
  | () when c = 2 -> "[" ^ a ^ "]"
  | () when c = 3 -> "to=" ^ a ^ ","
  | () when c = 4 -> " " ^ a ^ " "
  | () -> a

let offset_of (c : int) : int =
  match () with
  | () when c = 0 -> 0
  | () when c = 3 -> 3
  | () -> 1

(* The hex byte at [p] becomes a g, which is not a hex byte. *)
let break_at (p : int) (a : string) : string =
  take p a ^ "g" ^ drop (p + 1) a

(* The twin breaks one thing and keeps the context. *)
let twin_of (b : int) (p : int) (a : string) : string =
  match () with
  | () when b = 0 -> "0X" ^ drop 2 a
  | () when b = 1 -> break_at p a
  | () when b = 2 -> a ^ "1"
  | () when b = 3 -> "a" ^ a
  | () -> take 41 a

let rec gen_cases (seed : int) (n : int) (acc : pcase list) : pcase list =
  match () with
  | () when n <= 0 -> acc
  | () ->
    let seed, hs = gen_hex seed 40 [] in
    let a : string = "0x" ^ str_of_chars hs in
    let s1 : int = next seed in
    let ctx : int = rem_small (draw s1) 5 in
    let s2 : int = next s1 in
    let broke : int = rem_small ((draw s2) lsr 4) 5 in
    let s3 : int = next s2 in
    let pos : int = 2 + rem_small ((draw s3) lsr 6) 40 in
    gen_cases s3 (n - 1)
      ({ text = in_context ctx a;
         broken = in_context ctx (twin_of broke pos a);
         off = offset_of ctx;
         ctx;
         broke }
      :: acc)

let cases : pcase list = gen_cases 2024 200 []

(* The address in its context is the only candidate, and it is what
   resolution keeps: it starts first, and no other detector's
   candidate straddles either end of it. *)
let fires (p : pcase) : bool =
  Eth_address.find p.text = [ (p.off, p.off + 42) ]
  && Detect.scan p.text = [ sp p.off (p.off + 42) ]

(* The twin may still read as a PAN or an SSN;  it is never an
   address. *)
let stays_twin (p : pcase) : bool =
  Eth_address.find p.broken = [] && not (has_addr p.broken)

(* What the twin text itself must show for each breaking.  This reads
   the produced string, not the recorded index. *)
let shows_breaking (i : int) (p : pcase) : bool =
  match () with
  | () when i = 0 -> take 1 (drop (p.off + 1) p.broken) = "X"
  | () when i = 1 -> String.contains p.broken 'g'
  | () when i = 2 -> String.length p.broken = String.length p.text + 1
  | () when i = 3 ->
    String.length p.broken = String.length p.text + 1
    && take 1 (drop p.off p.broken) = "a"
  | () -> String.length p.broken = String.length p.text - 1

let checks : (string * bool) list =
  [ (* A. forms that fire *)
    ("addr: the zero address is 42 bytes", addr_length zero);
    ("addr: the zero address fires alone", addr_find zero);
    ("addr: the zero address is an Eth_address span", addr_scan zero);
    ("addr: the zero address scrubs to the token", addr_scrub zero);
    ("addr: WETH is 42 bytes", addr_length weth);
    ("addr: WETH fires alone", addr_find weth);
    ("addr: WETH is an Eth_address span", addr_scan weth);
    ("addr: WETH scrubs to the token", addr_scrub weth);
    ("addr: USDC is 42 bytes", addr_length usdc);
    ("addr: USDC fires alone", addr_find usdc);
    ("addr: USDC is an Eth_address span", addr_scan usdc);
    ("addr: USDC scrubs to the token", addr_scrub usdc);
    ("addr: the account address is 42 bytes", addr_length vitalik);
    ("addr: the account address fires alone", addr_find vitalik);
    ("addr: the account address is an Eth_address span", addr_scan vitalik);
    ("addr: the account address scrubs to the token", addr_scrub vitalik);
    ("addr: the all-f address is 42 bytes", addr_length ff);
    ("addr: the all-f address fires alone", addr_find ff);
    ("addr: the all-f address is an Eth_address span", addr_scan ff);
    ("addr: the all-f address scrubs to the token", addr_scrub ff);
    ("addr: lowercase WETH is 42 bytes", addr_length weth_lower);
    ("addr: lowercase WETH fires alone", addr_find weth_lower);
    ("addr: lowercase WETH is an Eth_address span", addr_scan weth_lower);
    ("addr: lowercase WETH scrubs to the token", addr_scrub weth_lower);
    ("addr: uppercase-hex WETH is 42 bytes", addr_length weth_upper);
    ("addr: uppercase-hex WETH fires alone", addr_find weth_upper);
    ("addr: uppercase-hex WETH is an Eth_address span", addr_scan weth_upper);
    ("addr: uppercase-hex WETH scrubs to the token", addr_scrub weth_upper);
    ( "addr: two addresses in a JSON object",
      Eth_address.find ("{\"from\":\"" ^ weth ^ "\",\"to\":\"" ^ usdc ^ "\"}")
      = [ (9, 51); (59, 101) ] );
    ( "addr: after a key and an equals sign",
      Eth_address.find ("to=" ^ weth) = [ (3, 45) ] );
    ( "addr: in brackets",
      Eth_address.find ("[" ^ weth ^ "]") = [ (1, 43) ] );
    ( "addr: in parentheses",
      Eth_address.find ("(" ^ weth ^ ")") = [ (1, 43) ] );
    ("addr: before a comma", Eth_address.find (weth ^ ",") = [ (0, 42) ]);
    ( "addr: between underscores",
      Eth_address.find ("_" ^ weth ^ "_") = [ (1, 43) ] );
    ( "addr: between two-byte UTF-8 chars",
      Eth_address.find (e_acute ^ weth ^ e_acute) = [ (2, 44) ] );
    ("addr: before a newline", Eth_address.find (weth ^ "\n") = [ (0, 42) ]);
    ( "addr: two addresses split by a space",
      Eth_address.find (weth ^ " " ^ zero) = [ (0, 42); (43, 85) ] );
    ( "addr: two addresses split by a space are two spans",
      Detect.scan (weth ^ " " ^ zero) = [ sp 0 42; sp 43 85 ] );
    ( "addr: a key, an address and a comma scrub to the token",
      scrub ("to=" ^ weth ^ ",") = "to=<eth_address>," );
    (* B. controls that stay *)
    ("stay: thirty-nine hex bytes", stays (take 41 weth));
    ("stay: forty-one hex bytes", stays (weth ^ "0"));
    ("stay: an uppercase X in the prefix", stays ("0X" ^ drop 2 weth));
    ("stay: the prefix without its zero", stays (drop 1 weth));
    ("stay: the prefix without its x", stays ("0" ^ drop 2 weth));
    ( "stay: a g as the first hex byte",
      stays (take 2 weth ^ "g" ^ drop 3 weth) );
    ( "stay: a G in the middle of the hex",
      stays (take 21 weth ^ "G" ^ drop 22 weth) );
    ("stay: a z as the last hex byte", stays (take 41 weth ^ "z"));
    ("stay: a letter glued before", stays ("a" ^ weth));
    ("stay: a digit glued before", stays ("1" ^ weth));
    ("stay: a letter glued after", stays (weth ^ "g"));
    ("stay: a digit glued after", stays (weth ^ "7"));
    ("stay: an x glued after", stays (weth ^ "x"));
    ("stay: thirty-nine hex bytes then a dash", stays (take 41 weth ^ "-"));
    ("stay: the empty string", stays "");
    ("stay: the prefix alone", stays "0x");
    ( "stay: a two-byte UTF-8 char inside the hex",
      stays (take 20 weth ^ e_acute ^ drop 22 weth) );
    ("stay: two addresses back to back", stays (weth ^ zero));
    ( "stay: a fullwidth zero inside the hex",
      stays (take 20 weth ^ fw_zero ^ drop 21 weth) );
    (* C. exhaustive byte sweeps *)
    ( "sweep-byte: 194 predecessor bytes leave the WETH span",
      sweep_count (predecessor weth) (1, 43) = 194 );
    ( "sweep-byte: a predecessor of WETH closes the window on alnum",
      sweep_rule (predecessor weth) (1, 43) not_alnum );
    ( "sweep-byte: 194 successor bytes leave the WETH span",
      sweep_count (successor weth) (0, 42) = 194 );
    ( "sweep-byte: a successor of WETH closes the window on alnum",
      sweep_rule (successor weth) (0, 42) not_alnum );
    ( "sweep-byte: 1 byte 0 of WETH opens the window",
      sweep_count (at0 weth) (0, 42) = 1 );
    ( "sweep-byte: only a zero opens the WETH window",
      sweep_rule (at0 weth) (0, 42) is_zero );
    ( "sweep-byte: 1 byte 1 of WETH opens the window",
      sweep_count (at1 weth) (0, 42) = 1 );
    ( "sweep-byte: only an x opens the WETH window",
      sweep_rule (at1 weth) (0, 42) is_x );
    ( "sweep-byte: 22 first hex bytes of WETH fire",
      sweep_count (at2 weth) (0, 42) = 22 );
    ( "sweep-byte: the first hex byte of WETH fires on hex",
      sweep_rule (at2 weth) (0, 42) t_hex );
    ( "sweep-byte: 22 middle hex bytes of WETH fire",
      sweep_count (at21 weth) (0, 42) = 22 );
    ( "sweep-byte: a middle hex byte of WETH fires on hex",
      sweep_rule (at21 weth) (0, 42) t_hex );
    ( "sweep-byte: 22 last hex bytes of WETH fire",
      sweep_count (at41 weth) (0, 42) = 22 );
    ( "sweep-byte: the last hex byte of WETH fires on hex",
      sweep_rule (at41 weth) (0, 42) t_hex );
    ( "sweep-byte: 194 predecessor bytes leave the zero-address span",
      sweep_count (predecessor zero) (1, 43) = 194 );
    ( "sweep-byte: a predecessor of the zero address closes on alnum",
      sweep_rule (predecessor zero) (1, 43) not_alnum );
    ( "sweep-byte: 194 successor bytes leave the zero-address span",
      sweep_count (successor zero) (0, 42) = 194 );
    ( "sweep-byte: a successor of the zero address closes on alnum",
      sweep_rule (successor zero) (0, 42) not_alnum );
    ( "sweep-byte: 1 byte 0 of the zero address opens the window",
      sweep_count (at0 zero) (0, 42) = 1 );
    ( "sweep-byte: only a zero opens the zero-address window",
      sweep_rule (at0 zero) (0, 42) is_zero );
    ( "sweep-byte: 1 byte 1 of the zero address opens the window",
      sweep_count (at1 zero) (0, 42) = 1 );
    ( "sweep-byte: only an x opens the zero-address window",
      sweep_rule (at1 zero) (0, 42) is_x );
    ( "sweep-byte: 22 first hex bytes of the zero address fire",
      sweep_count (at2 zero) (0, 42) = 22 );
    ( "sweep-byte: the first hex byte of the zero address fires on hex",
      sweep_rule (at2 zero) (0, 42) t_hex );
    ( "sweep-byte: 22 middle hex bytes of the zero address fire",
      sweep_count (at21 zero) (0, 42) = 22 );
    ( "sweep-byte: a middle hex byte of the zero address fires on hex",
      sweep_rule (at21 zero) (0, 42) t_hex );
    ( "sweep-byte: 22 last hex bytes of the zero address fire",
      sweep_count (at41 zero) (0, 42) = 22 );
    ( "sweep-byte: the last hex byte of the zero address fires on hex",
      sweep_rule (at41 zero) (0, 42) t_hex );
    ( "sweep-byte: 194 predecessor bytes leave the account span",
      sweep_count (predecessor vitalik) (1, 43) = 194 );
    ( "sweep-byte: a predecessor of the account closes on alnum",
      sweep_rule (predecessor vitalik) (1, 43) not_alnum );
    ( "sweep-byte: 194 successor bytes leave the account span",
      sweep_count (successor vitalik) (0, 42) = 194 );
    ( "sweep-byte: a successor of the account closes on alnum",
      sweep_rule (successor vitalik) (0, 42) not_alnum );
    ( "sweep-byte: 1 byte 0 of the account opens the window",
      sweep_count (at0 vitalik) (0, 42) = 1 );
    ( "sweep-byte: only a zero opens the account window",
      sweep_rule (at0 vitalik) (0, 42) is_zero );
    ( "sweep-byte: 1 byte 1 of the account opens the window",
      sweep_count (at1 vitalik) (0, 42) = 1 );
    ( "sweep-byte: only an x opens the account window",
      sweep_rule (at1 vitalik) (0, 42) is_x );
    ( "sweep-byte: 22 first hex bytes of the account fire",
      sweep_count (at2 vitalik) (0, 42) = 22 );
    ( "sweep-byte: the first hex byte of the account fires on hex",
      sweep_rule (at2 vitalik) (0, 42) t_hex );
    ( "sweep-byte: 22 middle hex bytes of the account fire",
      sweep_count (at21 vitalik) (0, 42) = 22 );
    ( "sweep-byte: a middle hex byte of the account fires on hex",
      sweep_rule (at21 vitalik) (0, 42) t_hex );
    ( "sweep-byte: 22 last hex bytes of the account fire",
      sweep_count (at41 vitalik) (0, 42) = 22 );
    ( "sweep-byte: the last hex byte of the account fires on hex",
      sweep_rule (at41 vitalik) (0, 42) t_hex );
    ( "sweep-byte: is_alnum is the test predicate",
      List.for_all
        (fun (b : char) -> Eth_address.is_alnum b = t_alnum b)
        bytes );
    ( "sweep-byte: is_hex is the test predicate",
      List.for_all (fun (b : char) -> Eth_address.is_hex b = t_hex b) bytes );
    ( "sweep-byte: 62 alphanumeric bytes",
      count_true (List.map t_alnum bytes) = 62 );
    ("sweep-byte: 22 hex bytes", count_true (List.map t_hex bytes) = 22);
    (* D. the production surface *)
    ("scan: the PAN address is 42 bytes", String.length t1 = 42);
    ( "scan: the PAN inside the address is Luhn valid",
      Luhn.valid (digits visa) );
    ("scan: the PAN inside the address is a candidate", Pan.find t1
                                                        = [ (3, 19) ]);
    ("addr: an address whose hex holds a PAN", Eth_address.find t1
                                               = [ (0, 42) ]);
    ("scan: the address starts first and takes the PAN", Detect.scan t1
                                                         = [ sp 0 42 ]);
    ("scan: the SSN address is 42 bytes", String.length t2 = 42);
    ("scan: the SSN inside the address is a candidate", Ssn.find t2
                                                        = [ (3, 12) ]);
    ("scan: the address starts first and takes the SSN", Detect.scan t2
                                                         = [ sp 0 42 ]);
    ("scan: a digit run glued before an address", Detect.scan t4 = []);
    ("scan: an AWS window ends on the zero", Aws_key.find t5 = [ (0, 20) ]);
    ("stay: the address after that AWS window", Eth_address.find t5 = []);
    ("scan: the AWS key is the only span", Detect.scan t5 = [ sp_aws 0 20 ]);
    ( "scan: a PAN, a space, then an address",
      Detect.scan t6 = [ sp_pan 0 16; sp 17 59 ] );
    ( "scan: an address, a space, then an SSN",
      Detect.scan t7 = [ sp 0 42; sp_ssn 43 54 ] );
    ("scan: a base58 key glued before an address", Detect.scan t8
                                                   = [ sp_sol 0 43 ]);
    ("scan: an address glued before a base58 key", Detect.scan t9
                                                   = [ sp_sol 42 85 ]);
    ( "scan: an AWS key, a space, then an address",
      Detect.scan t10 = [ sp_aws 0 20; sp 21 63 ] );
    ("scan: two addresses back to back leave nothing",
      Detect.scan (weth ^ zero) = []);
    (* E. sweep *)
    ("sweep: 200 cases generated", List.length cases = 200);
    ("sweep: every generated address fires as one span",
      List.for_all fires cases);
    ("sweep: every broken twin stays", List.for_all stays_twin cases);
    ( "sweep: every twin differs from its text",
      List.for_all (fun (p : pcase) -> p.broken <> p.text) cases );
    ( "sweep: every twin shows the breaking recorded for it",
      List.for_all (fun (p : pcase) -> shows_breaking p.broke p) cases );
    ( "sweep: non-vacuous, each of the five breakings shows in a twin",
      List.for_all
        (fun (i : int) ->
          List.exists
            (fun (p : pcase) -> p.broke = i && shows_breaking i p)
            cases)
        (List.init 5 Fun.id) );
    ( "sweep: non-vacuous, each of the five contexts occurs",
      List.for_all
        (fun (i : int) -> List.exists (fun (p : pcase) -> p.ctx = i) cases)
        (List.init 5 Fun.id) );
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
  | 0 -> print_endline "test_eth_address: PASS"
  | _ ->
    print_endline "test_eth_address: FAIL";
    exit 1
