(* M18: the token function and the emit currency.  Group A pins the
   canonical value per detector (the separator forms of a card, the two
   spellings of an SSN, the three cases of an address, the two spans
   kept as they are);  group B pins the fingerprints and the tokens
   against the independent oracle, byte for byte, plus the width, the
   hex alphabet and the documented NUL boundary;  group C drives the
   production path off the two real fluent-bit 5.1.1 captures (decode,
   events, scrub, encode, decode again);  group D pins the post-scrub
   duplicate-key reject at every map level, and the records that stay
   clean;  group E pins the Message frame bytes and the growth bound;
   group F is a deterministic sweep over 200 planted records.

   No test builds a [Scrub.scrubbed] value: the type is abstract, so
   every value here comes back from [Scrub.record] and nothing else. *)

open Scrubline

(* Provenance as in test_ack.ml and test_forward.ml.
   cap_forward_ack: -p require_ack_response=true -- arity-3 Forward
   frame whose option map (chunk, size, fluent_signal) uses a
   NON-MINIMAL map32 header straight off the wire.
   cap_forward_int_time: -p time_as_integer=true -- arity-2 frame
   with no options element at all. *)
let cap_forward_ack : string =
   "\x93\xa7\x61\x70\x70\x2e\x6c\x6f\x67\x91\x92\x92\xd7\x00\x6a\x91" ^
   "\x2d\x46\x06\x47\x5c\x60\x80\x82\xa3\x6c\x6f\x67\xd9\x20\x70\x61" ^
   "\x79\x6d\x65\x6e\x74\x20\x6f\x6b\x20\x63\x61\x72\x64\x3d\x34\x31" ^
   "\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\xa6\x73" ^
   "\x74\x72\x65\x61\x6d\xa6\x73\x74\x64\x65\x72\x72\xdf\x00\x00\x00" ^
   "\x03\xa5\x63\x68\x75\x6e\x6b\xb8\x75\x49\x4f\x45\x39\x59\x74\x66" ^
   "\x39\x56\x6b\x46\x79\x7a\x47\x76\x54\x30\x46\x42\x37\x51\x3d\x3d" ^
   "\xa4\x73\x69\x7a\x65\x01\xad\x66\x6c\x75\x65\x6e\x74\x5f\x73\x69" ^
   "\x67\x6e\x61\x6c\x00"

let cap_forward_int_time : string =
   "\x92\xa7\x61\x70\x70\x2e\x6c\x6f\x67\x91\x92\xce\x6a\x91\x2d\x4d" ^
   "\x82\xa3\x6c\x6f\x67\xd9\x20\x70\x61\x79\x6d\x65\x6e\x74\x20\x6f" ^
   "\x6b\x20\x63\x61\x72\x64\x3d\x34\x31\x31\x31\x31\x31\x31\x31\x31" ^
   "\x31\x31\x31\x31\x31\x31\x31\xa6\x73\x74\x72\x65\x61\x6d\xa6\x73" ^
   "\x74\x64\x65\x72\x72"

let sp_pan (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Pan; start = a; stop = b }

let sp_ssn (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Ssn; start = a; stop = b }

let sp_aws (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Aws_key; start = a; stop = b }

let sp_sol (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Sol_pubkey; start = a; stop = b }

let sp_eth (a : int) (b : int) : Detect.span =
  { Detect.detector = Detect.Eth_address; start = a; stop = b }

(* Sweep support: the deterministic LCG from test_pan. *)
let next (seed : int) : int = (seed * 1103515245 + 12345) land 0x3fffffff

let rec rem_small (v : int) (m : int) : int =
  match () with
  | () when m <= 0 -> 0
  | () when v < m -> v
  | () -> rem_small (v - m) m

let str_of_chars (cs : char list) : string = String.of_seq (List.to_seq cs)

let chars (s : string) : char list = List.of_seq (String.to_seq s)

(* The first [n] bytes, and the bytes after them;  total on any [n]. *)
let take (n : int) (s : string) : string =
  str_of_chars (List.filteri (fun (i : int) (_ : char) -> i < n) (chars s))

let drop (n : int) (s : string) : string =
  str_of_chars (List.filteri (fun (i : int) (_ : char) -> i >= n) (chars s))

(* Substring test over char lists;  total. *)
let rec is_prefix (p : char list) (s : char list) : bool =
  match (p, s) with
  | [], (_ : char list) -> true
  | (_ : char) :: (_ : char list), [] -> false
  | a :: pt, b :: st -> a = b && is_prefix pt st

let rec contains_l (p : char list) (s : char list) : bool =
  is_prefix p s
  ||
  match s with
  | [] -> false
  | (_ : char) :: tl -> contains_l p tl

let contains (hay : string) (needle : string) : bool =
  contains_l (chars needle) (chars hay)

(* The first event of a captured frame. *)
let first_event (cap : string) : Forward.event option =
  Option.bind (Result.to_option (Forward.decode cap))
    (fun ((f : Forward.frame), (_ : Forward.options)) ->
      Option.bind (Result.to_option (Forward.events f))
        (fun (es : Forward.event list) -> List.nth_opt es 0))

let ev (tag : string) (time : Forward.time) (record : Forward.record) :
    Forward.event =
  { Forward.tag; time; record }

(* The scrubbed value and spans, or None on the reject. *)
let scrubbed ~(salt : string) (e : Forward.event) :
    (Scrub.scrubbed * Detect.span list) option =
  Result.to_option (Scrub.record ~salt e)

let bytes_of ~(salt : string) (e : Forward.event) : string option =
  Option.map
    (fun ((s : Scrub.scrubbed), (_ : Detect.span list)) -> Scrub.encode s)
    (scrubbed ~salt e)

let dup : Err.t = Err.Malformed Gate_core.Duplicate_key

let visa : string = "4111111111111111"
let mc : string = "5500000000000004"
let ssn : string = "123-45-6789"
let aws : string = "AKIAIOSFODNN7EXAMPLE"
let weth : string = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
let weth_lower : string = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
let sol : string = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
let pepper : string = "pepper"
(* Oracle pins: fp8 under salt "pepper" unless said. *)
let fp_visa : string = "54c88f44"
let fp_visa_unsalted : string = "d9267da1"
let fp_visa_other : string = "7506871b"      (* salt "other" *)
let fp_ssn : string = "22deee47"
let fp_aws : string = "c1325844"
let fp_weth : string = "0fd19432"
let fp_sol : string = "d2fbc050"
let fp_mc : string = "28992464"
let fp_109 : string = "ed8662d5"            (* "1094111111111111111" *)
let fp_visa2 : string = "f38f48da"          (* "4111111111111112" *)
let tok_visa : string = "[REDACTED:pan:54c88f44]"
let tok_ssn : string = "[REDACTED:ssn:22deee47]"
let tok_aws : string = "[REDACTED:aws_key:c1325844]"
let tok_sol : string = "[REDACTED:sol_pubkey:d2fbc050]"
let tok_weth : string = "[REDACTED:eth_address:0fd19432]"
let tok_mc : string = "[REDACTED:pan:28992464]"

(* One capture check: decode the frame, take its first event, scrub it
   under [salt], then judge the event, the value and its spans. *)
let on_capture (cap : string) ~(salt : string)
    (f : Forward.event -> Scrub.scrubbed -> Detect.span list -> bool) : bool =
  Option.fold ~none:false
    ~some:(fun (e : Forward.event) ->
      Option.fold ~none:false
        ~some:(fun ((s : Scrub.scrubbed), (sp : Detect.span list)) ->
          f e s sp)
        (scrubbed ~salt e))
    (first_event cap)

(* A record under a salt, as the exact result, tag "t" and time 1. *)
let res ~(salt : string) (fields : Forward.record) :
    (Scrub.scrubbed * Detect.span list, Err.t) result =
  Scrub.record ~salt (ev "t" (Forward.Seconds 1) fields)

let ok_spans ~(salt : string) (fields : Forward.record) :
    Detect.span list option =
  Option.map
    (fun ((_ : Scrub.scrubbed), (sp : Detect.span list)) -> sp)
    (Result.to_option (res ~salt fields))

let ok_fields ~(salt : string) (fields : Forward.record) :
    Forward.record option =
  Option.map
    (fun ((s : Scrub.scrubbed), (_ : Detect.span list)) -> Scrub.fields s)
    (Result.to_option (res ~salt fields))

(* The length of a Str value;  -1 on every other shape. *)
let str_len (v : Msgpack.t) : int =
  match v with
  | Msgpack.Str s -> String.length s
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Bin _ | Msgpack.Arr _ | Msgpack.Map _
  | Msgpack.Ext (_, _) -> -1

(* The emitted frame decodes back as the Message it came from, with no
   options: an emitted frame carries no upstream chunk. *)
let roundtrips ~(salt : string) (tag : string) (e : Forward.event) : bool =
  Option.fold ~none:false
    ~some:(fun ((s : Scrub.scrubbed), (_ : Detect.span list)) ->
      Forward.decode (Scrub.encode s)
      = Ok
          ( Forward.Message
              { Forward.tag; time = Scrub.time s; record = Scrub.fields s },
            [] ))
    (scrubbed ~salt e)

(* F. the deterministic sweep.  One LCG walk draws the field count, the
   plant per field and the salt.  Bits 8 to 23 only: the low bits of an
   LCG cycle too fast, and a full 30-bit draw would make [rem_small]
   walk too far (test_eth_address.ml). *)
let draw (seed : int) : int = (seed lsr 8) land 0xffff

let plant_text (plant : int) : string =
  match () with
  | () when plant = 0 -> visa
  | () when plant = 1 -> ssn
  | () when plant = 2 -> aws
  | () when plant = 3 -> weth
  | () when plant = 4 -> sol
  | () -> "hello"

type pcase = {
  e : Forward.event;
  salt : string;
  planted : string list;
  in_key : bool;
  n : int;
}

(* [n] fields off the walk.  Field 0 puts its plant in the KEY on one
   draw in four;  every other field carries it in the value. *)
let build_fields (n : int) (seed : int) :
    Forward.record * string list * bool * int =
  let rec go (i : int) (seed : int) (fields : Forward.record)
      (planted : string list) (in_key : bool) :
      Forward.record * string list * bool * int =
    match () with
    | () when i >= n -> (List.rev fields, List.rev planted, in_key, seed)
    | () ->
      let w : int = next seed in
      let d : int = draw w in
      let plant : int = rem_small d 6 in
      let text : string = plant_text plant in
      let key_slot : bool = i = 0 && rem_small (d lsr 12) 4 = 0 && plant <> 5 in
      let field : string * Msgpack.t =
        match () with
        | () when key_slot -> (text, Msgpack.Str "x")
        | () -> ("k" ^ string_of_int i, Msgpack.Str ("v=" ^ text ^ ";"))
      in
      let planted : string list =
        match () with
        | () when plant = 5 -> planted
        | () -> text :: planted
      in
      go (i + 1) w (field :: fields) planted (in_key || key_slot)
  in
  go 0 seed [] [] false

let cases : pcase list =
  let rec go (k : int) (seed : int) (acc : pcase list) : pcase list =
    match () with
    | () when k <= 0 -> List.rev acc
    | () ->
      let v : int = next seed in
      let d : int = draw v in
      let n : int = 1 + rem_small d 4 in
      let fields, planted, in_key, seed2 = build_fields n v in
      let salt : string = "s" ^ string_of_int (rem_small (d lsr 3) 3) in
      let e : Forward.event =
        ev "sweep" (Forward.Seconds (rem_small d 1000)) fields
      in
      go (k - 1) seed2 ({ e; salt; planted; in_key; n } :: acc)
  in
  go 200 7 []

let sweep_spans (c : pcase) : Detect.span list option =
  Option.map
    (fun ((_ : Scrub.scrubbed), (sp : Detect.span list)) -> sp)
    (scrubbed ~salt:c.salt c.e)

let planted_cases : int =
  List.length (List.filter (fun (c : pcase) -> c.planted <> []) cases)

let checks : (string * bool) list =
  [ (* A. the canonical value, one spelling per value. *)
    ( "canon: pan drops space separators",
      Scrub.canonical Detect.Pan "4111 1111 1111 1111" = visa );
    ( "canon: pan drops dash separators",
      Scrub.canonical Detect.Pan "4111-1111-1111-1111" = visa );
    ("canon: bare pan is itself", Scrub.canonical Detect.Pan visa = visa);
    ( "canon: pan keeps an unrelated prefix",
      Scrub.canonical Detect.Pan "109 4111111111111111"
      = "1094111111111111111" );
    ("canon: ssn drops its dashes", Scrub.canonical Detect.Ssn ssn = "123456789");
    ( "canon: bare ssn is itself",
      Scrub.canonical Detect.Ssn "123456789" = "123456789" );
    ( "canon: eth mixed case lowercases",
      Scrub.canonical Detect.Eth_address weth = weth_lower );
    ( "canon: lowercase eth is itself",
      Scrub.canonical Detect.Eth_address weth_lower = weth_lower );
    ( "canon: uppercase-hex eth lowercases",
      Scrub.canonical Detect.Eth_address
        ("0x" ^ String.uppercase_ascii (drop 2 weth))
      = weth_lower );
    ("canon: aws key is kept as is", Scrub.canonical Detect.Aws_key aws = aws);
    ("canon: sol pubkey is kept as is", Scrub.canonical Detect.Sol_pubkey sol = sol);
    ( "canon: sol pubkey keeps its case",
      contains (Scrub.canonical Detect.Sol_pubkey sol) "T" );
    ( "canon: a split card rejoins without its separator",
      Scrub.canonical Detect.Pan (take 8 visa ^ " " ^ drop 8 visa) = visa );
    ("canon: space is a separator", Scrub.is_separator ' ');
    ("canon: dash is a separator", Scrub.is_separator '-');
    ("canon: dot is not a separator", not (Scrub.is_separator '.'));
    ("canon: slash is not a separator", not (Scrub.is_separator '/'));
    ("canon: newline is not a separator", not (Scrub.is_separator '\n'));
    ("canon: a digit is not a separator", not (Scrub.is_separator '0'));
    (* B. fingerprints and tokens against the oracle. *)
    ("fp: unsalted visa", Scrub.fp8 ~salt:"" visa = fp_visa_unsalted);
    ("fp: peppered visa", Scrub.fp8 ~salt:pepper visa = fp_visa);
    ("fp: visa under another salt", Scrub.fp8 ~salt:"other" visa = fp_visa_other);
    ("fp: bare ssn digits", Scrub.fp8 ~salt:pepper "123456789" = fp_ssn);
    ("fp: aws key", Scrub.fp8 ~salt:pepper aws = fp_aws);
    ("fp: lowercase eth address", Scrub.fp8 ~salt:pepper weth_lower = fp_weth);
    ("fp: sol pubkey", Scrub.fp8 ~salt:pepper sol = fp_sol);
    ("fp: mastercard", Scrub.fp8 ~salt:pepper mc = fp_mc);
    ( "fp: the m13 prefix residual",
      Scrub.fp8 ~salt:pepper "1094111111111111111" = fp_109 );
    ( "fp: a neighbouring card differs",
      Scrub.fp8 ~salt:pepper "4111111111111112" = fp_visa2 );
    ("fp: the width is eight hex chars", String.length (Scrub.fp8 ~salt:"" "") = 8);
    ( "fp: every char is lowercase hex",
      List.for_all
        (fun (c : char) -> List.mem c (chars "0123456789abcdef"))
        (chars (Scrub.fp8 ~salt:pepper visa)) );
    ( "fp: the nul boundary is not defended",
      Scrub.fp8 ~salt:"a\x00" "b" = Scrub.fp8 ~salt:"a" "\x00b" );
    ( "fp: token of a bare card",
      Scrub.token ~salt:pepper Detect.Pan visa = tok_visa );
    ( "fp: token of a spaced card",
      Scrub.token ~salt:pepper Detect.Pan "4111 1111 1111 1111" = tok_visa );
    ( "fp: token of a dashed card",
      Scrub.token ~salt:pepper Detect.Pan "4111-1111-1111-1111" = tok_visa );
    ("fp: token of an ssn", Scrub.token ~salt:pepper Detect.Ssn ssn = tok_ssn);
    ( "fp: token of an aws key",
      Scrub.token ~salt:pepper Detect.Aws_key aws = tok_aws );
    ( "fp: token of a sol pubkey",
      Scrub.token ~salt:pepper Detect.Sol_pubkey sol = tok_sol );
    ( "fp: token of an eth address",
      Scrub.token ~salt:pepper Detect.Eth_address weth = tok_weth );
    ( "fp: token of the lowercase eth address is the same",
      Scrub.token ~salt:pepper Detect.Eth_address weth_lower = tok_weth );
    ( "fp: another salt moves the token",
      Scrub.token ~salt:"other" Detect.Pan visa = "[REDACTED:pan:7506871b]" );
    ( "fp: an empty salt is accepted",
      Scrub.token ~salt:"" Detect.Pan visa = "[REDACTED:pan:d9267da1]" );
    ("fp: a pan token is 23 bytes", String.length tok_visa = 23);
    ("fp: an ssn token is 23 bytes", String.length tok_ssn = 23);
    ("fp: an aws_key token is 27 bytes", String.length tok_aws = 27);
    ("fp: a sol_pubkey token is 30 bytes", String.length tok_sol = 30);
    ("fp: an eth_address token is 31 bytes", String.length tok_weth = 31);
    ( "fp: every detector names itself in its token",
      List.for_all
        (fun (d : Detect.detector) ->
          contains
            (Scrub.token ~salt:pepper d "x")
            ("[REDACTED:" ^ Detect.to_string d ^ ":"))
        [ Detect.Pan; Detect.Ssn; Detect.Aws_key; Detect.Sol_pubkey;
          Detect.Eth_address ] );
    (* C. the production path off the real captures. *)
    ( "capture: the int-time frame yields an event",
      Option.is_some (first_event cap_forward_int_time) );
    ( "capture: the ack frame yields an event",
      Option.is_some (first_event cap_forward_ack) );
    ( "capture: int-time spans name the card",
      on_capture cap_forward_int_time ~salt:pepper
        (fun (_ : Forward.event) (_ : Scrub.scrubbed)
             (sp : Detect.span list) -> sp = [ sp_pan 16 32 ]) );
    ( "capture: int-time fields are scrubbed",
      on_capture cap_forward_int_time ~salt:pepper
        (fun (_ : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) ->
          Scrub.fields s
          = [ ("log", Msgpack.Str ("payment ok card=" ^ tok_visa));
              ("stream", Msgpack.Str "stderr") ]) );
    ( "capture: the tag rides verbatim",
      on_capture cap_forward_int_time ~salt:pepper
        (fun (_ : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) -> Scrub.tag s = "app.log") );
    ( "capture: the time rides verbatim",
      on_capture cap_forward_int_time ~salt:pepper
        (fun (e : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) -> Scrub.time s = e.Forward.time) );
    ( "capture: the int time is the captured second",
      on_capture cap_forward_int_time ~salt:pepper
        (fun (_ : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) ->
          Scrub.time s = Forward.Seconds 1787899213) );
    ( "capture: int-time frame bytes pinned",
      on_capture cap_forward_int_time ~salt:pepper
        (fun (_ : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) ->
          Scrub.encode s
          = "\x93\xa7app.log"
            ^ Msgpack.encode (Msgpack.Int 1787899213)
            ^ "\x82\xa3log\xd9\x27payment ok card=[REDACTED:pan:54c88f44]"
            ^ "\xa6stream\xa6stderr") );
    ( "capture: no card byte reaches the wire",
      on_capture cap_forward_int_time ~salt:pepper
        (fun (_ : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) -> not (contains (Scrub.encode s) visa)) );
    ( "capture: int-time frame decodes back as a message",
      on_capture cap_forward_int_time ~salt:pepper
        (fun (_ : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) ->
          Forward.decode (Scrub.encode s)
          = Ok
              ( Forward.Message
                  { Forward.tag = "app.log";
                    time = Scrub.time s;
                    record = Scrub.fields s },
                [] )) );
    ( "capture: ack-frame spans name the card",
      on_capture cap_forward_ack ~salt:pepper
        (fun (_ : Forward.event) (_ : Scrub.scrubbed)
             (sp : Detect.span list) -> sp = [ sp_pan 16 32 ]) );
    ( "capture: the event time rides verbatim",
      on_capture cap_forward_ack ~salt:pepper
        (fun (_ : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) ->
          Scrub.time s
          = Forward.Event_time
              { sec = 1787899206; nsec = 105340000 }) );
    ( "capture: event-time frame bytes pinned",
      on_capture cap_forward_ack ~salt:pepper
        (fun (_ : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) ->
          Scrub.encode s
          = "\x93\xa7app.log\xd7\x00\x6a\x91\x2d\x46\x06\x47\x5c\x60"
            ^ "\x82\xa3log\xd9\x27payment ok card=[REDACTED:pan:54c88f44]"
            ^ "\xa6stream\xa6stderr") );
    ( "capture: the event-time frame is 79 bytes",
      on_capture cap_forward_ack ~salt:pepper
        (fun (_ : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) -> String.length (Scrub.encode s) = 79) );
    ( "capture: event-time frame decodes back with no options",
      on_capture cap_forward_ack ~salt:pepper
        (fun (_ : Forward.event) (s : Scrub.scrubbed)
             (_ : Detect.span list) ->
          Forward.decode (Scrub.encode s)
          = Ok
              ( Forward.Message
                  { Forward.tag = "app.log";
                    time = Scrub.time s;
                    record = Scrub.fields s },
                [] )) );
    ( "capture: an unsalted emit differs from a salted one",
      Option.fold ~none:false
        ~some:(fun (e : Forward.event) ->
          bytes_of ~salt:"" e <> bytes_of ~salt:pepper e)
        (first_event cap_forward_int_time) );
    ( "capture: the same salt emits the same bytes",
      Option.fold ~none:false
        ~some:(fun (e : Forward.event) ->
          bytes_of ~salt:pepper e = bytes_of ~salt:pepper e)
        (first_event cap_forward_int_time) );
    (* D. the post-scrub duplicate-key reject. *)
    ( "dup: two spellings of one card meet on one token",
      res ~salt:pepper
        [ ("4111 1111 1111 1111", Msgpack.Str "a"); (visa, Msgpack.Str "b") ]
      = Error dup );
    ( "dup: a literal token already present as a key",
      res ~salt:pepper [ (visa, Msgpack.Str "a"); (tok_visa, Msgpack.Str "b") ]
      = Error dup );
    ( "dup: another salt moves the token off the literal",
      ok_spans ~salt:"other"
        [ (visa, Msgpack.Str "a"); (tok_visa, Msgpack.Str "b") ]
      = Some [ sp_pan 0 16 ] );
    ( "dup: a nested map is checked too",
      res ~salt:pepper
        [ ( "m",
            Msgpack.Map
              [ (Msgpack.Str "4111-1111-1111-1111", Msgpack.Str "a");
                (Msgpack.Str visa, Msgpack.Str "b") ] ) ]
      = Error dup );
    ( "dup: two levels down is checked too",
      res ~salt:pepper
        [ ( "m",
            Msgpack.Map
              [ ( Msgpack.Str "k",
                  Msgpack.Map
                    [ (Msgpack.Str "4111-1111-1111-1111", Msgpack.Str "a");
                      (Msgpack.Str visa, Msgpack.Str "b") ] ) ] ) ]
      = Error dup );
    ( "dup: a map under an array is checked too",
      res ~salt:pepper
        [ ( "a",
            Msgpack.Arr
              [ Msgpack.Int 1;
                Msgpack.Map
                  [ (Msgpack.Str "4111-1111-1111-1111", Msgpack.Str "a");
                    (Msgpack.Str visa, Msgpack.Str "b") ] ] ) ]
      = Error dup );
    ( "dup: distinct cards keep distinct tokens",
      ok_fields ~salt:pepper [ (visa, Msgpack.Str "a"); (mc, Msgpack.Str "b") ]
      = Some [ (tok_visa, Msgpack.Str "a"); (tok_mc, Msgpack.Str "b") ] );
    ( "dup: distinct cards report a span each",
      ok_spans ~salt:pepper [ (visa, Msgpack.Str "a"); (mc, Msgpack.Str "b") ]
      = Some [ sp_pan 0 16; sp_pan 0 16 ] );
    ( "dup: a non-str key never collides with a str one",
      Result.is_ok
        (res ~salt:pepper
           [ ( "m",
               Msgpack.Map
                 [ (Msgpack.Int 1, Msgpack.Str visa);
                   (Msgpack.Str "1", Msgpack.Str "x") ] ) ]) );
    ( "dup: equal values never collide",
      ok_spans ~salt:pepper
        [ ("a", Msgpack.Str visa); ("b", Msgpack.Str visa) ]
      = Some [ sp_pan 0 16; sp_pan 0 16 ] );
    ( "dup: a clean record still passes the check",
      ok_spans ~salt:pepper [ ("k", Msgpack.Str "v") ] = Some [] );
    ( "dup: a clean record rides through unchanged",
      ok_fields ~salt:pepper [ ("k", Msgpack.Str "v") ]
      = Some [ ("k", Msgpack.Str "v") ] );
    ( "dup: a bin payload is opaque",
      ok_spans ~salt:pepper [ ("b", Msgpack.Bin visa) ] = Some [] );
    ( "dup: a bin payload rides through unchanged",
      ok_fields ~salt:pepper [ ("b", Msgpack.Bin visa) ]
      = Some [ ("b", Msgpack.Bin visa) ] );
    ( "dup: a key alone is scrubbed",
      ok_fields ~salt:pepper [ (visa, Msgpack.Str "x") ]
      = Some [ (tok_visa, Msgpack.Str "x") ] );
    ( "dup: a key alone reports its span",
      ok_spans ~salt:pepper [ (visa, Msgpack.Str "x") ]
      = Some [ sp_pan 0 16 ] );
    ( "dup: an ssn value reports an ssn span",
      ok_spans ~salt:pepper [ ("k", Msgpack.Str ssn) ] = Some [ sp_ssn 0 11 ] );
    ( "dup: an aws key reports an aws_key span",
      ok_spans ~salt:pepper [ ("k", Msgpack.Str aws) ] = Some [ sp_aws 0 20 ] );
    ( "dup: a sol pubkey reports a sol_pubkey span",
      ok_spans ~salt:pepper [ ("k", Msgpack.Str sol) ] = Some [ sp_sol 0 43 ] );
    ( "dup: an eth address reports an eth_address span",
      ok_spans ~salt:pepper [ ("k", Msgpack.Str weth) ] = Some [ sp_eth 0 42 ] );
    (* E. the frame bytes. *)
    ( "frame: an int time takes the int slot",
      bytes_of ~salt:pepper (ev "t" (Forward.Seconds 1) [ ("k", Msgpack.Str "v") ])
      = Some "\x93\xa1t\x01\x81\xa1k\xa1v" );
    ( "frame: an event time takes the fixext 8 slot",
      bytes_of ~salt:pepper
        (ev "app.log"
           (Forward.Event_time { sec = 1787899206; nsec = 105340000 })
           [ ("k", Msgpack.Str "v") ])
      = Some "\x93\xa7app.log\xd7\x00\x6a\x91\x2d\x46\x06\x47\x5c\x60\x81\xa1k\xa1v" );
    ( "frame: an empty record is an empty map",
      bytes_of ~salt:pepper (ev "t" (Forward.Seconds 0) [])
      = Some "\x93\xa1t\x00\x80" );
    ( "frame: the int-time frame is a message with no options",
      roundtrips ~salt:pepper "t"
        (ev "t" (Forward.Seconds 1) [ ("k", Msgpack.Str "v") ]) );
    ( "frame: the event-time frame is a message with no options",
      roundtrips ~salt:pepper "app.log"
        (ev "app.log"
           (Forward.Event_time { sec = 1787899206; nsec = 105340000 })
           [ ("k", Msgpack.Str "v") ]) );
    ( "frame: a bare ssn becomes its token",
      ok_fields ~salt:pepper [ ("k", Msgpack.Str "123456789") ]
      = Some [ ("k", Msgpack.Str tok_ssn) ] );
    ( "frame: the worst span grows to 23 bytes",
      Option.fold ~none:false
        ~some:(fun (r : Forward.record) ->
          List.map (fun ((_ : string), (v : Msgpack.t)) -> str_len v) r
          = [ 23 ])
        (ok_fields ~salt:pepper [ ("k", Msgpack.Str "123456789") ]) );
    (* F. the deterministic sweep. *)
    ("sweep: two hundred cases", List.length cases = 200);
    ( "sweep: every case is accepted",
      List.for_all
        (fun (c : pcase) -> Option.is_some (scrubbed ~salt:c.salt c.e))
        cases );
    ( "sweep: one span per planted secret",
      List.for_all
        (fun (c : pcase) ->
          Option.fold ~none:false
            ~some:(fun (sp : Detect.span list) ->
              List.length sp = List.length c.planted)
            (sweep_spans c))
        cases );
    ( "sweep: no planted text survives the emit",
      List.for_all
        (fun (c : pcase) ->
          Option.fold ~none:false
            ~some:(fun (b : string) ->
              List.for_all (fun (t : string) -> not (contains b t)) c.planted)
            (bytes_of ~salt:c.salt c.e))
        cases );
    ( "sweep: every frame decodes back as its message",
      List.for_all
        (fun (c : pcase) -> roundtrips ~salt:c.salt "sweep" c.e)
        cases );
    ( "sweep: the emit is deterministic",
      List.for_all
        (fun (c : pcase) ->
          bytes_of ~salt:c.salt c.e = bytes_of ~salt:c.salt c.e)
        cases );
    ( "sweep: another salt moves exactly the planted cases",
      List.for_all
        (fun (c : pcase) ->
          (bytes_of ~salt:(c.salt ^ "!") c.e <> bytes_of ~salt:c.salt c.e)
          = (c.planted <> []))
        cases );
    ( "sweep: every detector is planted somewhere",
      List.for_all
        (fun (t : string) ->
          List.exists (fun (c : pcase) -> List.mem t c.planted) cases)
        [ visa; ssn; aws; weth; sol ] );
    ( "sweep: some field carries no secret",
      List.exists
        (fun (c : pcase) -> List.length c.planted < c.n)
        cases );
    ("sweep: some case plants in the key", List.exists (fun (c : pcase) -> c.in_key) cases);
    ("sweep: some case has four fields", List.exists (fun (c : pcase) -> c.n = 4) cases);
    ("sweep: at least a hundred cases are dirty", planted_cases >= 100);
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
  | 0 -> print_endline "test_scrub: PASS"
  | _ ->
    print_endline "test_scrub: FAIL";
    exit 1
