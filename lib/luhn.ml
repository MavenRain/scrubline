(* M13: the Luhn mod-10 check, total over a digit list.  A digit is
   an int in [0, 9];  anything else is not a digit and the check fails
   closed on it.  The PAN detector (pan.ml) uses it as its semantic
   filter: a digit run that fails Luhn is not a card number.

   Definition: from the rightmost digit leftward, every second digit
   is doubled and a doubled value above 9 has 9 subtracted;  the
   number is valid when the sum of the resulting digits is a multiple
   of 10.  The running sum is kept below 10 by subtraction (each
   contribution is at most 9), so there is no division and no modulus
   anywhere.  The empty list is the empty sum and reads as valid;  the
   caller gates the length. *)

type acc =
  | Bad
  | Sum of int * bool (* the reduced sum in [0, 9];  double the next digit? *)

let contribution (d : int) (double : bool) : int =
  match () with
  | () when double && d >= 5 -> (2 * d) - 9
  | () when double -> 2 * d
  | () -> d

let reduce (s : int) : int =
  match () with
  | () when s >= 10 -> s - 10
  | () -> s

let step (a : acc) (d : int) : acc =
  match a with
  | Bad -> Bad
  | Sum (s, double) -> (
    match () with
    | () when d < 0 || d > 9 -> Bad
    | () -> Sum (reduce (s + contribution d double), not double))

(* Digits arrive as read, most significant first;  the fold walks
   them from the right. *)
let valid (digits : int list) : bool =
  match List.fold_left step (Sum (0, false)) (List.rev digits) with
  | Bad -> false
  | Sum (s, (_ : bool)) -> s = 0
