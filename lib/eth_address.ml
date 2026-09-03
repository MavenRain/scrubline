(* M17: the Ethereum address candidate finder.  A candidate is a
   42-byte window of the decoded string.  Its first two bytes are the
   prefix 0x, with a lowercase x;  the next forty are hex bytes, an
   ASCII digit or a letter a..f in either case.  The byte before the
   window is not an ASCII alphanumeric byte (or the window starts the
   string) and the byte after it is not one (or the window ends the
   string);  an underscore, a dash, a dot, a slash, a quote, a
   bracket, a space, a newline, a NUL or a byte of a multi-byte UTF-8
   char next to it is fine.

   Every window opens on a '0' whose predecessor is not alphanumeric,
   so each start yields at most one window, and no two address
   windows overlap: a byte inside a window has an alphanumeric byte
   before it.

   EIP-55 case is not checked.  A mixed-case, a lowercase and an
   uppercase address all fire, which is the safe side: the checksum
   would only narrow the set that is redacted.

   Overlaps with other detectors resolve in detect.ml (leftmost, then
   longest, then table order, then the M18b union);  an address whose
   hex holds a Luhn-valid or an SSN-shaped digit run resolves to the
   address, which starts first and absorbs it.  No contiguous digit
   run crosses either end of a window, because both neighbours are
   non-digits and the x breaks a run, and a base58 run inside the hex
   starts after the x or after a 0 and ends at or before the window
   end.  A dashed SSN can straddle the right edge, though: its digit
   groups join across '-', a legal window successor, so the hex tail
   123 and a following -45-6789 read as one SSN.  Since M18b the union
   in resolve absorbs that candidate into the address span, so no byte
   of it survives.

   An address glued to an alphanumeric byte on either side stays: a
   digit run before it, a letter after it, a base58 key on either
   side, or two addresses back to back.  When an AWS key window ends
   on the 0 of 0x the key fires and the address bytes stay in the
   clear.  These are under-redactions, held for the M19 corpus.

   The walk is a char-list fold: no indexing, no loop keyword, tail
   calls only;  from each start it reads at most 43 bytes. *)

(* ASCII letters and digits: the adjacency class that closes a window. *)
let is_alnum (c : char) : bool =
  ('0' <= c && c <= '9') || ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z')

(* The hex bytes, either case. *)
let is_hex (c : char) : bool =
  ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')

(* The prefix of the detectors table, and the input after it. *)
let prefix (t : char list) : char list option =
  match t with
  | '0' :: 'x' :: tl -> Some tl
  | (_ : char list) -> None

(* Exactly [n] hex bytes at the front of [t], and the input after them. *)
let rec take_hex (n : int) (t : char list) : char list option =
  match () with
  | () when n <= 0 -> Some t
  | () -> (
    match t with
    | c :: tl when is_hex c -> take_hex (n - 1) tl
    | (_ : char list) -> None)

(* A window may end only where no alphanumeric byte follows. *)
let ends_clean (t : char list) : bool =
  match t with
  | [] -> true
  | c :: (_ : char list) -> not (is_alnum c)

(* Forty hex bytes after the two-byte prefix: forty-two in all. *)
let hex_len : int = 40

let width : int = 42

(* The window at [start], if the input from there reads as one. *)
let candidate ~(start : int) (t : char list) : (int * int) option =
  Option.bind (prefix t) (fun (t : char list) ->
      Option.bind (take_hex hex_len t) (fun (rest : char list) ->
          match () with
          | () when ends_clean rest -> Some (start, start + width)
          | () -> None))

(* Every '0' whose predecessor is not alphanumeric opens a window
   attempt.  Pairs come back ascending by start and pairwise disjoint. *)
let find (s : string) : (int * int) list =
  let rec go (i : int) (prev_alnum : bool) (t : char list)
      (acc : (int * int) list) : (int * int) list =
    match t with
    | [] -> List.rev acc
    | c :: tl ->
      let acc =
        match () with
        | () when c = '0' && not prev_alnum ->
          Option.fold ~none:acc
            ~some:(fun (w : int * int) -> w :: acc)
            (candidate ~start:i t)
        | () -> acc
      in
      go (i + 1) (is_alnum c) tl acc
  in
  go 0 false (List.of_seq (String.to_seq s)) []
