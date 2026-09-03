(* M15: the AWS access-key-id candidate finder.  A candidate is a
   20-byte window of the decoded string.  Its first four bytes are the
   prefix AKIA or ASIA;  the next sixteen are key bytes, an uppercase
   ASCII letter or an ASCII digit.  The byte before the window is not a
   key byte (or the window starts the string) and the byte after it is
   not a key byte (or the window ends the string);  a lowercase letter,
   a quote, a space, a dash, a slash, an equals sign or a byte of a
   multi-byte UTF-8 char next to it is fine.

   Every window opens on an 'A' whose predecessor is not a key byte, so
   each start yields at most one window, and no two key windows
   overlap: a byte inside a window has a key byte before it.

   Overlaps with other detectors resolve in detect.ml (leftmost, then
   longest, then table order);  a key whose tail holds a Luhn-valid or
   an SSN-shaped digit run resolves to the key, which starts first, and
   a key right after a digit run stays, because a digit is a key byte.

   The walk is a char-list fold: no indexing, no loop keyword, tail
   calls only;  from each start it reads at most 21 bytes. *)

(* Uppercase ASCII letters and ASCII digits: the key alphabet, and the
   adjacency class that closes a window. *)
let is_key_char (c : char) : bool =
  ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')

(* The two prefixes of the detectors table, and the input after one. *)
let prefix (t : char list) : char list option =
  match t with
  | 'A' :: 'K' :: 'I' :: 'A' :: tl -> Some tl
  | 'A' :: 'S' :: 'I' :: 'A' :: tl -> Some tl
  | (_ : char list) -> None

(* Exactly [n] key bytes at the front of [t], and the input after them. *)
let rec take_key (n : int) (t : char list) : char list option =
  match () with
  | () when n <= 0 -> Some t
  | () -> (
    match t with
    | c :: tl when is_key_char c -> take_key (n - 1) tl
    | (_ : char list) -> None)

(* A window may end only where no key byte follows. *)
let ends_clean (t : char list) : bool =
  match t with
  | [] -> true
  | c :: (_ : char list) -> not (is_key_char c)

(* Sixteen key bytes after the four-byte prefix: twenty in all. *)
let tail_len : int = 16

let width : int = 20

(* The window at [start], if the input from there reads as one. *)
let candidate ~(start : int) (t : char list) : (int * int) option =
  Option.bind (prefix t) (fun (t : char list) ->
      Option.bind (take_key tail_len t) (fun (rest : char list) ->
          match () with
          | () when ends_clean rest -> Some (start, start + width)
          | () -> None))

(* Every 'A' whose predecessor is not a key byte opens a window attempt.
   Pairs come back ascending by start and pairwise disjoint. *)
let find (s : string) : (int * int) list =
  let rec go (i : int) (prev_key : bool) (t : char list)
      (acc : (int * int) list) : (int * int) list =
    match t with
    | [] -> List.rev acc
    | c :: tl ->
      let acc =
        match () with
        | () when c = 'A' && not prev_key ->
          Option.fold ~none:acc
            ~some:(fun (w : int * int) -> w :: acc)
            (candidate ~start:i t)
        | () -> acc
      in
      go (i + 1) (is_key_char c) tl acc
  in
  go 0 false (List.of_seq (String.to_seq s)) []
