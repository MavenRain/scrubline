(* M16: the base58 decoder.  The alphabet is the Bitcoin one: the
   digits without 0, the letters without O, I and l, fifty-eight bytes
   in all.  The value of a byte comes from its ASCII range, so the
   decoder needs no table and no indexing.

   The value builds up in little-endian byte limbs.  Each digit
   multiplies the limbs by 58 and adds its value;  the carry ripples up
   and becomes a new top limb when it is not zero.  A leading '1' is
   not part of the value: each one denotes one zero byte at the front,
   counted while nothing else has been read.

   The decode is all or nothing.  One byte outside the alphabet and the
   whole string reads as None.

   The cost is quadratic in the length, since every digit walks every
   limb.  The only lib caller is sol_pubkey.ml, which bounds the input
   to 44 bytes.

   The walk is a pair of folds over lists: no indexing, no loop
   keyword, no exception. *)

(* The Bitcoin alphabet: the digits without 0, the letters without O, I
   and l.  Fifty-eight bytes. *)
let alphabet : string =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

(* The digit value of a byte, by ASCII range: 9 digits, then the letter
   ranges A..H, J..N, P..Z, a..k, m..z (8 + 5 + 11 + 11 + 14).  None
   outside the alphabet. *)
let value (c : char) : int option =
  let k : int = Char.code c in
  match () with
  | () when '1' <= c && c <= '9' -> Some (k - Char.code '1')
  | () when 'A' <= c && c <= 'H' -> Some (k - Char.code 'A' + 9)
  | () when 'J' <= c && c <= 'N' -> Some (k - Char.code 'J' + 17)
  | () when 'P' <= c && c <= 'Z' -> Some (k - Char.code 'P' + 22)
  | () when 'a' <= c && c <= 'k' -> Some (k - Char.code 'a' + 33)
  | () when 'm' <= c && c <= 'z' -> Some (k - Char.code 'm' + 44)
  | () -> None

let is_digit (c : char) : bool = Option.is_some (value c)

(* Multiply the little-endian byte limbs by 58 and add [v].  The carry
   ripples up and becomes a new top limb when it is not zero.  With [v]
   below 58 the carry stays below 58, so one extra limb is enough, and
   the top limb is never zero. *)
let mul58_add (limbs : int list) (v : int) : int list =
  let rev, carry =
    List.fold_left
      (fun ((acc : int list), (carry : int)) (b : int) ->
        let x : int = (b * 58) + carry in
        ((x land 255) :: acc, x lsr 8))
      ([], v) limbs
  in
  match () with
  | () when carry > 0 -> List.rev (carry :: rev)
  | () -> List.rev rev

(* The decode state: leading '1' bytes counted while nothing else has
   been read, then the value limbs. *)
type state = { leading : int; in_lead : bool; limbs : int list }

let step (st : state) (v : int) : state =
  match () with
  | () when st.in_lead && v = 0 -> { st with leading = st.leading + 1 }
  | () -> { st with in_lead = false; limbs = mul58_add st.limbs v }

(* The bytes a base58 string denotes: one zero byte per leading '1',
   then the big-endian value.  None when any byte is outside the
   alphabet.  Quadratic in the length;  Sol_pubkey bounds the input
   to 44 bytes. *)
let decode (s : string) : string option =
  let chars : char list = List.of_seq (String.to_seq s) in
  let vs : int list = List.filter_map value chars in
  match () with
  | () when List.length vs <> List.length chars -> None
  | () ->
    let st : state =
      List.fold_left step { leading = 0; in_lead = true; limbs = [] } vs
    in
    Some
      (Bytesx.of_codes
         (List.init st.leading (fun (_ : int) -> 0) @ List.rev st.limbs))
