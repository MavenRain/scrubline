(* M13: the PAN candidate finder.  A candidate is a window of the
   decoded string that reads as a card number:

     - it starts on a digit whose predecessor is not a digit, and ends
       on a digit whose successor is not a digit (no digit adjacent to
       either end);
     - inside, digits are joined by at most one separator at a time,
       a single space or a single dash;
     - it holds 13 to 19 digits;
     - the digits pass Luhn.

   Every window that satisfies all four is a candidate;  the framework
   (detect.ml) resolves overlaps leftmost, then longest.  So a valid
   number after a short unrelated one ("100 4111...") is still found,
   while a run of 20 or more contiguous digits yields nothing: every
   shorter window inside it has a digit at one end.

   The walk is a char-list fold (the Reader idiom): no indexing, no
   loop keyword, tail calls only.  From each start the inner walk
   reads at most 19 digits and 18 separators, so it is bounded. *)

let is_digit (c : char) : bool = '0' <= c && c <= '9'

let is_sep (c : char) : bool = c = ' ' || c = '-'

(* Only ever applied to a char that passed [is_digit]. *)
let digit_of (c : char) : int = Char.code c - Char.code '0'

let min_digits : int = 13

let max_digits : int = 19

(* The next input char, classified, with the input after it. *)
type look =
  | Digit of char * char list
  | Sep of char list
  | Stop

let look (t : char list) : look =
  match t with
  | [] -> Stop
  | c :: tl -> (
    match () with
    | () when is_digit c -> Digit (c, tl)
    | () when is_sep c -> Sep tl
    | () -> Stop)

(* A digit run has just ended at index [i] with [n] digits read
   (reversed in [digits]).  The window [start, i + 1) is a candidate
   if it is long enough and passes Luhn. *)
let close ~(start : int) (i : int) (digits : int list) (n : int)
    (acc : (int * int) list) : (int * int) list =
  match () with
  | () when n >= min_digits && Luhn.valid (List.rev digits) ->
    (start, i + 1) :: acc
  | () -> acc

(* Read the digit [c] at index [i], then look past it.  A following
   digit extends the run;  a separator closes the run and, if a digit
   follows the separator, carries the window across it;  anything
   else closes the run and ends the walk.  Past [max_digits] digits
   the walk is abandoned: every longer window from this start is
   over the cap too. *)
let rec take_digit ~(start : int) (i : int) (c : char) (digits : int list)
    (n : int) (rest : char list) (acc : (int * int) list) :
    (int * int) list =
  let digits = digit_of c :: digits in
  let n = n + 1 in
  match () with
  | () when n > max_digits -> acc
  | () -> (
    match look rest with
    | Digit (d, tl) -> take_digit ~start (i + 1) d digits n tl acc
    | Sep tl -> (
      let acc = close ~start i digits n acc in
      match look tl with
      | Digit (d, tl') -> take_digit ~start (i + 2) d digits n tl' acc
      | Sep (_ : char list) -> acc
      | Stop -> acc)
    | Stop -> close ~start i digits n acc)

(* Every digit whose predecessor is not a digit opens a window walk.
   Pairs come back ascending by start, then by stop. *)
let find (s : string) : (int * int) list =
  let rec go (i : int) (prev_digit : bool) (t : char list)
      (acc : (int * int) list) : (int * int) list =
    match t with
    | [] -> List.rev acc
    | c :: tl ->
      let acc =
        match () with
        | () when is_digit c && not prev_digit ->
          take_digit ~start:i i c [] 0 tl acc
        | () -> acc
      in
      go (i + 1) (is_digit c) tl acc
  in
  go 0 false (List.of_seq (String.to_seq s)) []
