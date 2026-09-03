(* M16: the Solana pubkey detector.  Group A is the forms that fire and
   group B the controls that stay (a byte glued into the run, wrong
   decode lengths, a run broken inside, the other detectors' forms);
   group C sweeps all 256 byte values at every position the rule
   constrains, for three keys;  group D drives the production surface,
   which carries Pan, Ssn, Aws_key and Sol_pubkey at M16, including the
   overlaps where a key holds a PAN or an SSN;  group E is a
   deterministic sweep over generated keys in brackets, each with a
   broken twin, encoded by a test-side encoder that shares nothing with
   lib/base58.ml.  Bare [Sol_pubkey.find] pins are exact: runs never
   overlap, so the whole result is pinned. *)

open Scrubline

let sp (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Sol_pubkey; start = a; stop = b }

let sp_pan (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Pan; start = a; stop = b }

let sp_ssn (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Ssn; start = a; stop = b }

let sp_aws (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Aws_key; start = a; stop = b }

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

let bytes_of (codes : int list) : string = Bytesx.of_codes codes

let has_key (s : string) : bool =
  List.exists
    (fun (x : Detect.span) -> x.Detect.detector = Detect.Sol_pubkey)
    (Detect.scan s)

(* The SPL token program id and wrapped SOL, 43 bytes each. *)
let token : string = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

let wsol : string = "So11111111111111111111111111111111111111112"

let ones : string = String.make 32 '1'

let hello : string = "StV1DL6CwTryKyV"

let token_bytes : int list =
  [ 0x06; 0xdd; 0xf6; 0xe1; 0xd7; 0x65; 0xa1; 0x93; 0xd9; 0xcb; 0xe1;
    0x46; 0xce; 0xeb; 0x79; 0xac; 0x1c; 0xb4; 0x85; 0xed; 0x5f; 0x5b;
    0x37; 0x91; 0x3a; 0x8c; 0xf5; 0x85; 0x7e; 0xff; 0x00; 0xa9 ]

let wsol_bytes : int list =
  [ 0x06; 0x9b; 0x88; 0x57; 0xfe; 0xab; 0x81; 0x84; 0xfb; 0x68; 0x7f;
    0x63; 0x46; 0x18; 0xc0; 0x35; 0xda; 0xc4; 0x39; 0xdc; 0x1a; 0xeb;
    0x3b; 0x55; 0x98; 0xa0; 0xf0; 0x00; 0x00; 0x00; 0x00; 0x01 ]

let visa : string = "4111111111111111"

let ex : string = "AKIAIOSFODNN7EXAMPLE"

(* A fullwidth 1: three bytes, none of them in the alphabet. *)
let fw_one : string = "\xef\xbc\x91"

(* C. one string per byte value, at each position the rule constrains. *)
let successor (key : string) (b : char) : string = key ^ str1 b

let predecessor (key : string) (b : char) : string = str1 b ^ key

let last_replaced (key : string) (b : char) : string =
  take (String.length key - 1) key ^ str1 b

let first_replaced (key : string) (b : char) : string = str1 b ^ drop 1 key

(* How many of the 256 bytes leave exactly the span [w]. *)
let sweep_count (f : char -> string) (w : int * int) : int =
  count_true (List.map (fun (b : char) -> Sol_pubkey.find (f b) = [ w ]) bytes)

(* Which bytes leave that span, stated again as a predicate. *)
let sweep_rule (f : char -> string) (w : int * int) (p : char -> bool) : bool =
  List.for_all (fun (b : char) -> (Sol_pubkey.find (f b) = [ w ]) = p b) bytes

(* An alphabet byte grows the run to a different decode length, so the
   span is never the one the key alone leaves. *)
let not_digit (b : char) : bool = not (Base58.is_digit b)

let is_one (b : char) : bool = b = '1'

(* A first digit of 1, 2 or 3 leaves the value under 2^248, which is 31
   bytes;  a first '1' adds a zero byte to the 31-byte tail. *)
let first_ok (b : char) : bool =
  b = '1'
  || Option.fold ~none:false ~some:(fun (v : int) -> v >= 4) (Base58.value b)

(* D. a key whose bytes hold a PAN, one whose bytes hold an SSN, and
   the two glued neighbours. *)
let t1 : string = String.make 27 'z' ^ visa

let t2 : string = String.make 34 'z' ^ "123456789"

let t3 : string = visa ^ token

let t4 : string = "123-45-6789" ^ token

let fire_corpus : string list =
  [ token; wsol; ones; "2" ^ token; "2" ^ String.make 43 '1';
    String.make 31 '1' ^ "2"; String.make 43 'z'; "0" ^ token; token ^ "0";
    token ^ "l"; "O" ^ token ^ "I"; "\"" ^ token ^ "\""; token ^ "\n";
    "{\"pubkey\":\"" ^ token ^ "\"}";
    "https://explorer.solana.com/address/" ^ token;
    "pubkey=" ^ token ^ "&x=1"; token ^ " " ^ token; fw_one ^ token ]

(* E. the test-side encoder.  It shares nothing with lib/base58.ml, so
   agreement between the two is evidence. *)
let alphabet_chars : char list = chars Base58.alphabet

(* Quotient and remainder by 58, by repeated subtraction.  Total, and
   the input stays under 58 * 256 + 256, so it stops in 256 steps. *)
let divmod58 (x : int) : int * int =
  let rec go (x : int) (q : int) : int * int =
    match () with
    | () when x < 58 -> (q, x)
    | () -> go (x - 58) (q + 1)
  in
  go x 0

(* [ds] are little-endian base-58 digits.  Multiply them by 256, add
   the byte [b], then push the carry as further digits. *)
let mul256_add (ds : int list) (b : int) : int list =
  let rev, carry =
    List.fold_left
      (fun ((acc : int list), (carry : int)) (d : int) ->
        let q, r = divmod58 ((d * 256) + carry) in
        (r :: acc, q))
      ([], b) ds
  in
  let rec push (acc : int list) (carry : int) : int list =
    match () with
    | () when carry <= 0 -> acc
    | () ->
      let q, r = divmod58 carry in
      push (r :: acc) q
  in
  List.rev (push rev carry)

(* The leading zero bytes of a big-endian byte list. *)
let rec leading_zeros (v : int list) (n : int) : int =
  match v with
  | [] -> n
  | b :: tl -> (
    match () with
    | () when b = 0 -> leading_zeros tl (n + 1)
    | () -> n)

(* The base58 text of the big-endian bytes [v]: the digits come out
   little-endian, so they are reversed, and one '1' goes in front per
   leading zero byte. *)
let encode (v : int list) : string =
  let ds : int list = List.fold_left mul256_add [] v in
  let body : char list =
    List.map
      (fun (d : int) ->
        Option.value ~default:'1' (List.nth_opt alphabet_chars d))
      (List.rev ds)
  in
  String.make (leading_zeros v 0) '1' ^ str_of_chars body

(* One byte per LCG step, in generation order: the first byte generated
   is the first, most significant, byte of the key. *)
let rec gen_bytes (seed : int) (n : int) (acc : int list) : int * int list =
  match () with
  | () when n <= 0 -> (seed, List.rev acc)
  | () ->
    let seed = next seed in
    gen_bytes seed (n - 1) (((seed lsr 6) land 255) :: acc)

type pcase =
  { k : int;
    v : int list;
    key : string;
    text : string;
    broken : string;
    broke : int }

(* The twin breaks one thing, cycling over the five breakings by the
   case index, and keeps the brackets. *)
let twin_of (b : int) (key : string) : string =
  let mid : int = String.length key lsr 1 in
  match () with
  | () when b = 0 -> key ^ "22"
  | () when b = 1 -> take mid key ^ "0" ^ drop mid key
  | () when b = 2 -> take mid key ^ "l" ^ drop (mid + 1) key
  | () when b = 3 -> take 31 key
  | () -> key ^ key

let rec gen_cases (seed : int) (k : int) (n : int) (acc : pcase list) :
    pcase list =
  match () with
  | () when n <= 0 -> acc
  | () ->
    let seed, v = gen_bytes seed 32 [] in
    let key : string = encode v in
    let broke : int = rem_small k 5 in
    gen_cases seed (k + 1) (n - 1)
      ({ k;
         v;
         key;
         text = "[" ^ key ^ "]";
         broken = "[" ^ twin_of broke key ^ "]";
         broke }
      :: acc)

let cases : pcase list = gen_cases 2024 0 200 []

(* The bracketed key is the only candidate, and it is what resolution
   keeps: it starts first and is longest, so it wins over any PAN or
   SSN its bytes happen to hold. *)
let fires (p : pcase) : bool =
  let stop : int = 1 + String.length p.key in
  Sol_pubkey.find p.text = [ (1, stop) ] && Detect.scan p.text = [ sp 1 stop ]

(* The twin may still read as a PAN or an SSN;  it is never a key. *)
let stays (p : pcase) : bool =
  Sol_pubkey.find p.broken = [] && not (has_key p.broken)

(* What the twin text itself must show for each breaking.  This reads
   the produced string, not the recorded index. *)
let shows_breaking (i : int) (p : pcase) : bool =
  match () with
  | () when i = 0 ->
    String.ends_with ~suffix:"22]" p.broken
    && String.length p.broken = String.length p.text + 2
  | () when i = 1 ->
    String.contains p.broken '0'
    && String.length p.broken = String.length p.text + 1
  | () when i = 2 ->
    String.contains p.broken 'l'
    && String.length p.broken = String.length p.text
  | () when i = 3 -> String.length p.broken = 33
  | () -> String.length p.broken = (2 * String.length p.key) + 2

let checks : (string * bool) list =
  [ (* A. forms that fire *)
    ("key: the token program id", Sol_pubkey.find token = [ (0, 43) ]);
    ("key: wrapped SOL", Sol_pubkey.find wsol = [ (0, 43) ]);
    ("key: thirty-two ones", Sol_pubkey.find ones = [ (0, 32) ]);
    ( "key: a digit glued before a key is a new key",
      Sol_pubkey.find ("2" ^ token) = [ (0, 44) ] );
    ( "key: a 2 then forty-three ones",
      Sol_pubkey.find ("2" ^ String.make 43 '1') = [ (0, 44) ] );
    ( "key: thirty-one ones then a 2",
      Sol_pubkey.find (String.make 31 '1' ^ "2") = [ (0, 32) ] );
    ( "key: forty-three z",
      Sol_pubkey.find (String.make 43 'z') = [ (0, 43) ] );
    ("key: a 0 before closes the run", Sol_pubkey.find ("0" ^ token)
                                       = [ (1, 44) ]);
    ("key: a 0 after closes the run", Sol_pubkey.find (token ^ "0")
                                      = [ (0, 43) ]);
    ("key: an l after closes the run", Sol_pubkey.find (token ^ "l")
                                       = [ (0, 43) ]);
    ( "key: an O before and an I after",
      Sol_pubkey.find ("O" ^ token ^ "I") = [ (1, 44) ] );
    ( "key: quotes are not alphabet bytes",
      Sol_pubkey.find ("\"" ^ token ^ "\"") = [ (1, 44) ] );
    ("key: a newline after", Sol_pubkey.find (token ^ "\n") = [ (0, 43) ]);
    ( "key: in a JSON field",
      Sol_pubkey.find ("{\"pubkey\":\"" ^ token ^ "\"}") = [ (11, 54) ] );
    ( "key: in an explorer URL",
      Sol_pubkey.find ("https://explorer.solana.com/address/" ^ token)
      = [ (36, 79) ] );
    ( "key: in a query string",
      Sol_pubkey.find ("pubkey=" ^ token ^ "&x=1") = [ (7, 50) ] );
    ( "key: two keys split by a space",
      Sol_pubkey.find (token ^ " " ^ token) = [ (0, 43); (44, 87) ] );
    ( "key: a fullwidth digit before is three foreign bytes",
      Sol_pubkey.find (fw_one ^ token) = [ (3, 46) ] );
    (* B. controls that stay *)
    ("stay: a z glued before a key", Sol_pubkey.find ("z" ^ token) = []);
    ("stay: a 1 glued before a key", Sol_pubkey.find ("1" ^ token) = []);
    ("stay: a digit glued after a key", Sol_pubkey.find (token ^ "2") = []);
    ("stay: two keys glued", Sol_pubkey.find (token ^ token) = []);
    ("stay: a PAN glued before a key", Sol_pubkey.find (visa ^ token) = []);
    ( "stay: thirty ones then a 2",
      Sol_pubkey.find (String.make 30 '1' ^ "2") = [] );
    ("stay: thirty-three ones", Sol_pubkey.find (String.make 33 '1') = []);
    ("stay: forty-five ones", Sol_pubkey.find (String.make 45 '1') = []);
    ("stay: forty-four z", Sol_pubkey.find (String.make 44 'z') = []);
    ( "stay: the first forty-two token bytes",
      Sol_pubkey.find (take 42 token) = [] );
    ( "stay: the first thirty-one token bytes",
      Sol_pubkey.find (take 31 token) = [] );
    ( "stay: the first forty-two wsol bytes",
      Sol_pubkey.find (take 42 wsol) = [] );
    ( "stay: a 0 inside the key",
      Sol_pubkey.find (take 21 token ^ "0" ^ drop 21 token) = [] );
    ( "stay: an l replacing a key byte",
      Sol_pubkey.find (take 21 token ^ "l" ^ drop 22 token) = [] );
    ("stay: a PAN is not a key", Sol_pubkey.find visa = []);
    ("stay: an SSN is not a key", Sol_pubkey.find "123-45-6789" = []);
    ("stay: an AWS key is not a key", Sol_pubkey.find ex = []);
    ( "stay: the AWS secret access key",
      Sol_pubkey.find "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" = [] );
    ("stay: the empty string", Sol_pubkey.find "" = []);
    ("stay: one byte", Sol_pubkey.find "1" = []);
    ("stay: three bytes", Sol_pubkey.find "abc" = []);
    ("stay: fifteen bytes", Sol_pubkey.find hello = []);
    (* C. exhaustive byte sweeps *)
    ( "sweep-byte: 198 successor bytes leave the ones span",
      sweep_count (successor ones) (0, 32) = 198 );
    ( "sweep-byte: a successor of ones closes the run on the alphabet",
      sweep_rule (successor ones) (0, 32) not_digit );
    ( "sweep-byte: 198 predecessor bytes leave the ones span",
      sweep_count (predecessor ones) (1, 33) = 198 );
    ( "sweep-byte: a predecessor of ones closes the run on the alphabet",
      sweep_rule (predecessor ones) (1, 33) not_digit );
    ( "sweep-byte: 58 last bytes of ones fire",
      sweep_count (last_replaced ones) (0, 32) = 58 );
    ( "sweep-byte: the last byte of ones fires on the alphabet",
      sweep_rule (last_replaced ones) (0, 32) Base58.is_digit );
    ( "sweep-byte: 1 first byte of ones fires",
      sweep_count (first_replaced ones) (0, 32) = 1 );
    ( "sweep-byte: only a 1 opens the ones span",
      sweep_rule (first_replaced ones) (0, 32) is_one );
    ( "sweep-byte: 198 successor bytes leave the token span",
      sweep_count (successor token) (0, 43) = 198 );
    ( "sweep-byte: a successor of token closes the run on the alphabet",
      sweep_rule (successor token) (0, 43) not_digit );
    ( "sweep-byte: 198 predecessor bytes leave the token span",
      sweep_count (predecessor token) (1, 44) = 198 );
    ( "sweep-byte: a predecessor of token closes the run on the alphabet",
      sweep_rule (predecessor token) (1, 44) not_digit );
    ( "sweep-byte: 58 last bytes of token fire",
      sweep_count (last_replaced token) (0, 43) = 58 );
    ( "sweep-byte: the last byte of token fires on the alphabet",
      sweep_rule (last_replaced token) (0, 43) Base58.is_digit );
    ( "sweep-byte: 55 first bytes of token fire",
      sweep_count (first_replaced token) (0, 43) = 55 );
    ( "sweep-byte: the first byte of token fires on 1 and on 4 up",
      sweep_rule (first_replaced token) (0, 43) first_ok );
    ( "sweep-byte: 198 successor bytes leave the wsol span",
      sweep_count (successor wsol) (0, 43) = 198 );
    ( "sweep-byte: a successor of wsol closes the run on the alphabet",
      sweep_rule (successor wsol) (0, 43) not_digit );
    ( "sweep-byte: 198 predecessor bytes leave the wsol span",
      sweep_count (predecessor wsol) (1, 44) = 198 );
    ( "sweep-byte: a predecessor of wsol closes the run on the alphabet",
      sweep_rule (predecessor wsol) (1, 44) not_digit );
    ( "sweep-byte: 58 last bytes of wsol fire",
      sweep_count (last_replaced wsol) (0, 43) = 58 );
    ( "sweep-byte: the last byte of wsol fires on the alphabet",
      sweep_rule (last_replaced wsol) (0, 43) Base58.is_digit );
    ( "sweep-byte: 55 first bytes of wsol fire",
      sweep_count (first_replaced wsol) (0, 43) = 55 );
    ( "sweep-byte: the first byte of wsol fires on 1 and on 4 up",
      sweep_rule (first_replaced wsol) (0, 43) first_ok );
    (* D. the production surface *)
    ("scan: a key is a Sol_pubkey span", Detect.scan token = [ sp 0 43 ]);
    ("scrub: a key", scrub token = "<sol_pubkey>");
    ( "scrub: a key, a PAN, an SSN and an AWS key",
      scrub
        ("pubkey " ^ token ^ " card " ^ visa ^ " ssn 123-45-6789 key " ^ ex)
      = "pubkey <sol_pubkey> card <pan> ssn <ssn> key <aws_key>" );
    ("scan: the PAN inside a key is Luhn valid", Luhn.valid (digits t1));
    ("scan: the PAN inside a key is a candidate", Pan.find t1 = [ (27, 43) ]);
    ("key: a key whose bytes hold a PAN", Sol_pubkey.find t1 = [ (0, 43) ]);
    ("scan: the key starts first and takes the PAN", Detect.scan t1
                                                     = [ sp 0 43 ]);
    ("scrub: a key whose bytes hold a PAN", scrub t1 = "<sol_pubkey>");
    ("scan: the SSN inside a key is a candidate", Ssn.find t2 = [ (34, 43) ]);
    ("key: a key whose bytes hold an SSN", Sol_pubkey.find t2 = [ (0, 43) ]);
    ("scan: the key starts first and takes the SSN", Detect.scan t2
                                                     = [ sp 0 43 ]);
    ("scan: a PAN glued before a key", Pan.find t3 = [ (0, 16) ]);
    ("stay: a key glued after a PAN", Sol_pubkey.find t3 = []);
    ("scan: the glued PAN is the only span", Detect.scan t3
                                             = [ sp_pan 0 16 ]);
    ( "scan: a PAN, a space, then a key",
      Detect.scan (visa ^ " " ^ token) = [ sp_pan 0 16; sp 17 60 ] );
    ("scan: an SSN glued before a key", Ssn.find t4 = [ (0, 11) ]);
    ("stay: a key glued after an SSN", Sol_pubkey.find t4 = []);
    ("scan: the glued SSN is the only span", Detect.scan t4
                                             = [ sp_ssn 0 11 ]);
    ( "scan: an SSN, a space, then a key",
      Detect.scan ("123-45-6789 " ^ token) = [ sp_ssn 0 11; sp 12 55 ] );
    ( "scan: an AWS key, a space, then a key",
      Detect.scan (ex ^ " " ^ token) = [ sp_aws 0 20; sp 21 64 ] );
    ("scan: an AWS key glued before a key", Detect.scan (ex ^ token) = []);
    ( "tree: a key in a nested value is scrubbed",
      Detect.tree ~token:marker
        (Msgpack.Map
           [ (Msgpack.Str "pubkey", Msgpack.Arr [ Msgpack.Str token ]) ])
      = ( Msgpack.Map
            [ ( Msgpack.Str "pubkey",
                Msgpack.Arr [ Msgpack.Str "<sol_pubkey>" ] ) ],
          [ sp 0 43 ] ) );
    ( "record: a key in a field name is scrubbed",
      Detect.record ~token:marker [ (token, Msgpack.Str "x") ]
      = ([ ("<sol_pubkey>", Msgpack.Str "x") ], [ sp 0 43 ]) );
    ( "record: a Bin payload is never scanned",
      (let r = [ ("b", Msgpack.Bin token) ] in
       Detect.record ~token:marker r = (r, [])) );
    ( "scrub: every fire-corpus entry fires as a key",
      List.for_all has_key fire_corpus );
    ( "scrub: no fire-corpus entry is a key once scrubbed",
      List.for_all (fun (s : string) -> not (has_key (scrub s))) fire_corpus );
    (* E. sweep *)
    ("sweep: 200 cases generated", List.length cases = 200);
    ( "sweep: every case is 32 bytes",
      List.for_all (fun (p : pcase) -> List.length p.v = 32) cases );
    ("sweep: the encoder pins the token program id", encode token_bytes
                                                     = token);
    ("sweep: the encoder pins wrapped SOL", encode wsol_bytes = wsol);
    ( "sweep: the encoder pins thirty-two zero bytes",
      encode (List.init 32 (fun (_ : int) -> 0)) = ones );
    ("sweep: the encoder pins 1112", encode [ 0; 0; 0; 1 ] = "1112");
    ("sweep: the encoder pins 211", encode [ 13; 36 ] = "211");
    ("sweep: the encoder pins 21", encode [ 58 ] = "21");
    ("sweep: the encoder pins the empty string", encode [] = "");
    ("sweep: divmod58 of 3364", divmod58 3364 = (58, 0));
    ("sweep: divmod58 of 57", divmod58 57 = (0, 57));
    ("sweep: divmod58 of 14847", divmod58 14847 = (255, 57));
    ("sweep: mul256_add of no digits", mul256_add [] 5 = [ 5 ]);
    ("sweep: mul256_add carries past fifty-eight", mul256_add [ 1 ] 0
                                                   = [ 24; 4 ]);
    ( "sweep: every key is 43 or 44 bytes",
      List.for_all
        (fun (p : pcase) ->
          String.length p.key = 43 || String.length p.key = 44)
        cases );
    ( "sweep: 188 keys of length 44",
      count_true
        (List.map (fun (p : pcase) -> String.length p.key = 44) cases)
      = 188 );
    ( "sweep: 12 keys of length 43",
      count_true
        (List.map (fun (p : pcase) -> String.length p.key = 43) cases)
      = 12 );
    ( "sweep: 1 key starts with a 1",
      count_true
        (List.map
           (fun (p : pcase) -> String.starts_with ~prefix:"1" p.key)
           cases)
      = 1 );
    ( "sweep: case 0 is the oracle key",
      List.exists
        (fun (p : pcase) ->
          p.k = 0
          && p.key = "HjKfJCHp6jFiQrxLw9u5zS3oQEUQHAs9Ga2rZvynFYNC")
        cases );
    ( "sweep: case 199 is the oracle key",
      List.exists
        (fun (p : pcase) ->
          p.k = 199
          && p.key = "82py941uA69uKPmWUTrLUrENBBKKVFNMvLcadS5om48A")
        cases );
    ( "sweep: every key round trips through the decoder",
      List.for_all
        (fun (p : pcase) -> Base58.decode p.key = Some (bytes_of p.v))
        cases );
    ("sweep: every generated key fires as one span", List.for_all fires cases);
    ("sweep: every broken twin stays", List.for_all stays cases);
    ( "sweep: non-vacuous, each of the five breakings shows in a twin",
      List.for_all
        (fun (i : int) ->
          List.exists
            (fun (p : pcase) -> p.broke = i && shows_breaking i p)
            cases)
        (List.init 5 Fun.id) );
    ( "sweep: every twin shows the breaking recorded for it",
      List.for_all (fun (p : pcase) -> shows_breaking p.broke p) cases );
    ( "sweep: every twin differs from its text",
      List.for_all (fun (p : pcase) -> p.broken <> p.text) cases );
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
  | 0 -> print_endline "test_sol_pubkey: PASS"
  | _ ->
    print_endline "test_sol_pubkey: FAIL";
    exit 1
