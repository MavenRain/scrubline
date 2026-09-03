(* M16: the base58 decoder.  Group A pins exact decode vectors, group
   B the strings the decode rejects, group C the digit value at every
   alphabet range edge and just off it, group D sweeps all 256 byte
   values over the alphabet predicates, group E pins the limb multiply,
   and group F pins the decoded length at the boundaries the Solana
   pubkey rule leans on.  The vectors come from an independent oracle,
   never from the code under test. *)

open Scrubline

let count_true (bs : bool list) : int =
  List.fold_left (fun (n : int) (b : bool) -> if b then n + 1 else n) 0 bs

(* One char as a string, so the sweeps need no arithmetic on ints. *)
let str1 (c : char) : string = String.make 1 c

(* Every byte value once;  [Bytesx.chr] is total. *)
let bytes : char list = List.init 256 Bytesx.chr

let chars (s : string) : char list = List.of_seq (String.to_seq s)

let str_of_chars (cs : char list) : string = String.of_seq (List.to_seq cs)

(* The first [n] bytes, and the bytes after them;  total on any [n]. *)
let take (n : int) (s : string) : string =
  str_of_chars (List.filteri (fun (i : int) (_ : char) -> i < n) (chars s))

let drop (n : int) (s : string) : string =
  str_of_chars (List.filteri (fun (i : int) (_ : char) -> i >= n) (chars s))

let bytes_of (codes : int list) : string = Bytesx.of_codes codes

let len_of (s : string) : int option =
  Option.map String.length (Base58.decode s)

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

let checks : (string * bool) list =
  [ (* A. decode vectors *)
    ("decode: hello world", Base58.decode hello = Some "hello world");
    ( "decode: thirty-two ones are thirty-two zero bytes",
      Base58.decode ones = Some (String.make 32 '\x00') );
    ("decode: the token program id", Base58.decode token
                                     = Some (bytes_of token_bytes));
    ("decode: the token program id is 32 bytes", List.length token_bytes = 32);
    ("decode: wrapped SOL", Base58.decode wsol = Some (bytes_of wsol_bytes));
    ("decode: wrapped SOL is 32 bytes", List.length wsol_bytes = 32);
    ("decode: the empty string", Base58.decode "" = Some "");
    ("decode: 1 is one zero byte", Base58.decode "1" = Some (bytes_of [ 0 ]));
    ("decode: 2 is one", Base58.decode "2" = Some (bytes_of [ 1 ]));
    ("decode: z is fifty-seven", Base58.decode "z" = Some (bytes_of [ 57 ]));
    ("decode: 21 is fifty-eight", Base58.decode "21" = Some (bytes_of [ 58 ]));
    ( "decode: 211 is fifty-eight squared",
      Base58.decode "211" = Some (bytes_of [ 13; 36 ]) );
    ("decode: zz", Base58.decode "zz" = Some (bytes_of [ 13; 35 ]));
    ( "decode: 11z keeps both leading zero bytes",
      Base58.decode "11z" = Some (bytes_of [ 0; 0; 57 ]) );
    ("decode: 1112", Base58.decode "1112" = Some (bytes_of [ 0; 0; 0; 1 ]));
    ("decode: 11 is two zero bytes",
     Base58.decode "11" = Some (bytes_of [ 0; 0 ]));
    ( "decode: a leading 1 adds a zero byte to a key",
      Base58.decode ("1" ^ token) = Some (bytes_of (0 :: token_bytes)) );
    (* B. rejects *)
    ("reject: the digit 0", Base58.decode "0" = None);
    ("reject: the letter O", Base58.decode "O" = None);
    ("reject: the letter I", Base58.decode "I" = None);
    ("reject: the letter l", Base58.decode "l" = None);
    ("reject: a space inside", Base58.decode "1 1" = None);
    ("reject: an O after a digit", Base58.decode "1O" = None);
    ("reject: a dash", Base58.decode "-" = None);
    ("reject: plain text", Base58.decode "hello world" = None);
    ("reject: a 0 after a key", Base58.decode (token ^ "0") = None);
    ("reject: a fullwidth 1", Base58.decode "\xef\xbc\x91" = None);
    ("reject: a two-byte UTF-8 char", Base58.decode "\xc3\xa9" = None);
    ( "reject: a quoted key",
      Base58.decode ("\"" ^ token ^ "\"") = None );
    (* C. digit values *)
    ("value: 1 is zero", Base58.value '1' = Some 0);
    ("value: 9 is eight", Base58.value '9' = Some 8);
    ("value: A is nine", Base58.value 'A' = Some 9);
    ("value: H is sixteen", Base58.value 'H' = Some 16);
    ("value: J is seventeen", Base58.value 'J' = Some 17);
    ("value: N is twenty-one", Base58.value 'N' = Some 21);
    ("value: P is twenty-two", Base58.value 'P' = Some 22);
    ("value: Z is thirty-two", Base58.value 'Z' = Some 32);
    ("value: a is thirty-three", Base58.value 'a' = Some 33);
    ("value: k is forty-three", Base58.value 'k' = Some 43);
    ("value: m is forty-four", Base58.value 'm' = Some 44);
    ("value: z is fifty-seven", Base58.value 'z' = Some 57);
    ("value: the digit 0 has none", Base58.value '0' = None);
    ("value: the letter O has none", Base58.value 'O' = None);
    ("value: the letter I has none", Base58.value 'I' = None);
    ("value: the letter l has none", Base58.value 'l' = None);
    ("value: a space has none", Base58.value ' ' = None);
    ("value: an at sign has none", Base58.value '@' = None);
    ("value: a bracket has none", Base58.value '[' = None);
    ("value: a backquote has none", Base58.value '`' = None);
    ("value: a brace has none", Base58.value '{' = None);
    (* D. the alphabet over all 256 bytes *)
    ("alphabet: fifty-eight bytes", String.length Base58.alphabet = 58);
    ( "alphabet: the value of each byte is its place",
      List.for_all Fun.id
        (List.mapi
           (fun (i : int) (c : char) -> Base58.value c = Some i)
           (chars Base58.alphabet)) );
    ( "alphabet: the fifty-eight values are distinct",
      List.length (List.sort_uniq compare (List.filter_map Base58.value bytes))
      = 58 );
    ( "alphabet: fifty-eight of the 256 bytes are digits",
      count_true (List.map Base58.is_digit bytes) = 58 );
    ( "alphabet: is_digit is membership in the alphabet",
      List.for_all
        (fun (b : char) ->
          Base58.is_digit b = String.contains Base58.alphabet b)
        bytes );
    ( "alphabet: a byte has a value exactly when it is a digit",
      List.for_all
        (fun (b : char) -> Option.is_some (Base58.value b) = Base58.is_digit b)
        bytes );
    ( "alphabet: every value is under fifty-eight",
      List.for_all
        (fun (v : int) -> 0 <= v && v < 58)
        (List.filter_map Base58.value bytes) );
    ( "alphabet: one byte decodes exactly on the alphabet",
      List.for_all
        (fun (b : char) ->
          Option.is_some (Base58.decode (str1 b)) = Base58.is_digit b)
        bytes );
    (* E. the limb multiply *)
    ("limb: no limbs and no value", Base58.mul58_add [] 0 = []);
    ("limb: no limbs and a value", Base58.mul58_add [] 5 = [ 5 ]);
    ("limb: one limb times fifty-eight", Base58.mul58_add [ 1 ] 0 = [ 58 ]);
    ( "limb: the carry becomes a top limb",
      Base58.mul58_add [ 58 ] 0 = [ 36; 13 ] );
    ("limb: a full limb carries", Base58.mul58_add [ 255 ] 57 = [ 255; 57 ]);
    ( "limb: the carry ripples through two limbs",
      Base58.mul58_add [ 255; 255 ] 57 = [ 255; 255; 57 ] );
    ("limb: a zero low limb stays zero",
     Base58.mul58_add [ 0; 1 ] 0 = [ 0; 58 ]);
    (* F. decoded lengths *)
    ( "length: a leading 1 on a key is 33 bytes",
      len_of ("1" ^ token) = Some 33 );
    ("length: a z before a key is 33 bytes", len_of ("z" ^ token) = Some 33);
    ( "length: a digit after a key is 33 bytes",
      len_of (token ^ "2") = Some 33 );
    ("length: a 2 before a key is 32 bytes", len_of ("2" ^ token) = Some 32);
    ( "length: a 2 then forty-three ones is 32 bytes",
      len_of ("2" ^ String.make 43 '1') = Some 32 );
    ( "length: thirty-one ones then a 2 is 32 bytes",
      len_of (String.make 31 '1' ^ "2") = Some 32 );
    ( "length: thirty ones then a 2 is 31 bytes",
      len_of (String.make 30 '1' ^ "2") = Some 31 );
    ( "length: thirty-three ones are 33 bytes",
      len_of (String.make 33 '1') = Some 33 );
    ( "length: forty-five ones are 45 bytes",
      len_of (String.make 45 '1') = Some 45 );
    ( "length: forty-four z are 33 bytes",
      len_of (String.make 44 'z') = Some 33 );
    ("length: forty-three z are 32 bytes",
     len_of (String.make 43 'z') = Some 32);
    ( "length: the first forty-two token bytes are 31 bytes",
      len_of (take 42 token) = Some 31 );
    ( "length: the first thirty-one token bytes are 23 bytes",
      len_of (take 31 token) = Some 23 );
    ( "length: the first forty-two wsol bytes are 31 bytes",
      len_of (take 42 wsol) = Some 31 );
    ("length: two keys glued are 63 bytes", len_of (token ^ token) = Some 63);
    ("length: thirty-two ones are 32 bytes", len_of ones = Some 32);
    ("length: the empty string is 0 bytes", len_of "" = Some 0);
    ("length: the bytes after a cut", len_of (drop 42 token) = Some 1);
    ("length: a foreign byte has no length", len_of "0" = None);
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
  | 0 -> print_endline "test_base58: PASS"
  | _ ->
    print_endline "test_base58: FAIL";
    exit 1
