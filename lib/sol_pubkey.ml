(* M16: the Solana pubkey candidate finder.  A candidate is a maximal
   run of base58 bytes of the decoded string.  The alphabet is the only
   run boundary: any byte outside it closes a run (0, O, I, l, a space,
   a quote, punctuation, and every byte of a multi-byte UTF-8 char),
   and so does the end of the string.  The run reads as a key when its
   base58 decode is exactly 32 bytes, which is the only test.

   The length guard 32..44 is a work bound only: k digits denote at
   most k bytes and 45 digits denote at least 33, so a run outside that
   range can never decode to 32 bytes and is never decoded.

   Runs never overlap, so each run yields at most one span.

   Overlaps with other detectors resolve in detect.ml (leftmost, then
   longest, then table order);  a key whose bytes hold a Luhn-valid or
   an SSN-shaped digit run resolves to the key, which starts first or
   is longer.

   The walk is a char-list walk with a two-state cursor: no indexing,
   no loop keyword, tail calls only;  it decodes once per run of 32..44
   bytes. *)

let min_len : int = 32

let max_len : int = 44

let key_bytes : int = 32

(* A run reads as a key when its decode is exactly 32 bytes.  The length
   test is a work bound only: k digits denote at most k bytes and 45
   digits denote at least 33, so it never changes the answer. *)
let is_key (run : string) : bool =
  let n : int = String.length run in
  match () with
  | () when n < min_len || n > max_len -> false
  | () ->
    Option.fold ~none:false
      ~some:(fun (b : string) -> String.length b = key_bytes)
      (Base58.decode run)

(* The walk is between runs or inside one: the run start and its bytes
   in reverse. *)
type cursor =
  | Gap
  | Run of int * char list

let run_string (rev : char list) : string =
  String.of_seq (List.to_seq (List.rev rev))

(* A run that ends at [stop] adds its span when it reads as a key. *)
let close (cur : cursor) (stop : int) (acc : (int * int) list) :
    (int * int) list =
  match cur with
  | Gap -> acc
  | Run (start, rev) -> (
    match () with
    | () when is_key (run_string rev) -> (start, stop) :: acc
    | () -> acc)

let extend (cur : cursor) (i : int) (c : char) : cursor =
  match cur with
  | Gap -> Run (i, [ c ])
  | Run (start, rev) -> Run (start, c :: rev)

(* Every maximal alphabet run, left to right.  Pairs come back ascending
   by start and pairwise disjoint. *)
let find (s : string) : (int * int) list =
  let rec go (i : int) (cur : cursor) (t : char list)
      (acc : (int * int) list) : (int * int) list =
    match t with
    | [] -> List.rev (close cur i acc)
    | c :: tl -> (
      match () with
      | () when Base58.is_digit c -> go (i + 1) (extend cur i c) tl acc
      | () -> go (i + 1) Gap tl (close cur i acc))
  in
  go 0 Gap (List.of_seq (String.to_seq s)) []
