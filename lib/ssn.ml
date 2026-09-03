(* M14: the SSN candidate finder.  A candidate is a window of the
   decoded string that reads as a US Social Security number in one of
   two forms: dashed `ddd-dd-dddd` (11 bytes) or bare `ddddddddd` (9
   bytes).  It starts on a digit whose predecessor is not a digit and
   ends on a digit whose successor is not a digit (no digit adjacent
   to either end;  a dash, a space or a letter next to it is fine).
   Its area (the first three digits) is not 000, not 666 and not
   900..999;  its group (the next two) is not 00;  its serial (the
   last four) is not 0000.

   The fourth byte decides the form (a dash opens the dashed one, a
   digit the bare one), so each start yields at most one window, and
   no two SSN windows overlap: a digit inside a window has a digit or
   a dash before it, and a start right after an inner dash cannot
   read either form.

   Overlaps with other detectors resolve in detect.ml (leftmost, then
   longest, then table order);  a PAN window that contains an
   SSN-shaped window wins because it starts first.

   The walk is a char-list fold: no indexing, no loop keyword, tail
   calls only;  from each start it reads at most 11 bytes. *)

let is_digit (c : char) : bool = '0' <= c && c <= '9'

type area = char * char * char

type group = char * char

type serial = char * char * char * char

(* Exactly three digits at the front of [t], and the input after them. *)
let take3 (t : char list) : (area * char list) option =
  match t with
  | a :: b :: c :: tl when is_digit a && is_digit b && is_digit c ->
    Some ((a, b, c), tl)
  | (_ : char list) -> None

(* Exactly two digits at the front of [t], and the input after them. *)
let take2 (t : char list) : (group * char list) option =
  match t with
  | a :: b :: tl when is_digit a && is_digit b -> Some ((a, b), tl)
  | (_ : char list) -> None

(* Exactly four digits at the front of [t], and the input after them. *)
let take4 (t : char list) : (serial * char list) option =
  match t with
  | a :: b :: c :: d :: tl
    when is_digit a && is_digit b && is_digit c && is_digit d ->
    Some ((a, b, c, d), tl)
  | (_ : char list) -> None

(* The input after a leading dash. *)
let dash (t : char list) : char list option =
  match t with
  | '-' :: tl -> Some tl
  | (_ : char list) -> None

(* A window may end only where no digit follows. *)
let ends_clean (t : char list) : bool =
  match t with
  | [] -> true
  | c :: (_ : char list) -> not (is_digit c)

(* 000, 666 and 900..999 are never issued. *)
let area_ok ((a, b, c) : area) : bool =
  (not (a = '0' && b = '0' && c = '0'))
  && (not (a = '6' && b = '6' && c = '6'))
  && a <> '9'

(* 00 is never issued. *)
let group_ok ((a, b) : group) : bool = not (a = '0' && b = '0')

(* 0000 is never issued. *)
let serial_ok ((a, b, c, d) : serial) : bool =
  not (a = '0' && b = '0' && c = '0' && d = '0')

(* After the area: the group and serial of the dashed form, and the
   window width 11. *)
let dashed_tail (t : char list) : (group * serial * int * char list) option =
  Option.bind (take2 t) (fun ((g : group), (t : char list)) ->
      Option.bind (dash t) (fun (t : char list) ->
          Option.map
            (fun ((s : serial), (t : char list)) -> (g, s, 11, t))
            (take4 t)))

(* After the area: the group and serial of the bare form, width 9. *)
let bare_tail (t : char list) : (group * serial * int * char list) option =
  Option.bind (take2 t) (fun ((g : group), (t : char list)) ->
      Option.map
        (fun ((s : serial), (t : char list)) -> (g, s, 9, t))
        (take4 t))

(* The fourth byte decides the form: a dash opens the dashed one, and
   anything else is read as the bare one (which fails unless digits
   follow). *)
let tail (t : char list) : (group * serial * int * char list) option =
  match t with
  | [] -> None
  | c :: tl -> (
    match () with
    | () when c = '-' -> dashed_tail tl
    | () -> bare_tail t)

(* The window at [start], if the input from there reads as one. *)
let candidate ~(start : int) (t : char list) : (int * int) option =
  Option.bind (take3 t) (fun ((a : area), (t : char list)) ->
      Option.bind (tail t)
        (fun ((g : group), (s : serial), (width : int), (rest : char list)) ->
          match () with
          | ()
            when area_ok a && group_ok g && serial_ok s && ends_clean rest ->
            Some (start, start + width)
          | () -> None))

(* Every digit whose predecessor is not a digit opens a window attempt.
   Pairs come back ascending by start and pairwise disjoint. *)
let find (s : string) : (int * int) list =
  let rec go (i : int) (prev_digit : bool) (t : char list)
      (acc : (int * int) list) : (int * int) list =
    match t with
    | [] -> List.rev acc
    | c :: tl ->
      let acc =
        match () with
        | () when is_digit c && not prev_digit ->
          Option.fold ~none:acc
            ~some:(fun (w : int * int) -> w :: acc)
            (candidate ~start:i t)
        | () -> acc
      in
      go (i + 1) (is_digit c) tl acc
  in
  go 0 false (List.of_seq (String.to_seq s)) []
