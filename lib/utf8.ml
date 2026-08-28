(* M6: RFC 3629 validator, total over the byte string, one walk, first
   defect wins. The byte that PROVES the defect names the error, so a
   sequence that is both short and impossible reports the impossibility:

     lead 0x80..0xBF                      -> Bad_byte  (bare continuation)
     lead 0xC0/0xC1                       -> Overlong  (2-byte ASCII)
     lead 0xF5..0xFD                      -> Out_of_range (> U+10FFFF)
     lead 0xFE/0xFF                       -> Bad_byte
     0xE0 then 0x80..0x9F                 -> Overlong
     0xED then 0xA0..0xBF                 -> Surrogate (U+D800..U+DFFF)
     0xF0 then 0x80..0x8F                 -> Overlong
     0xF4 then 0x90..0xBF                 -> Out_of_range
     continuation slot outside 0x80..0xBF -> Bad_byte
     input ends mid-sequence              -> Truncated

   The char-list walk keeps it index-free (the Reader idiom). *)

let cont (b : int) : bool = 0x80 <= b && b <= 0xbf

let validate (s : string) : (unit, Gate_core.utf8_error) result =
  let rec go bytes =
    match bytes with
    | [] -> Ok ()
    | c :: tl -> lead (Char.code c) tl
  and lead b tl =
    match () with
    | () when b <= 0x7f -> go tl
    | () when b <= 0xbf -> Error Gate_core.Bad_byte
    | () when b <= 0xc1 -> Error Gate_core.Overlong
    | () when b <= 0xdf -> conts 1 tl
    | () when b = 0xe0 ->
      constrained ~lo:0xa0 ~hi:0xbf ~bad:Gate_core.Overlong ~more:1 tl
    | () when b = 0xed ->
      constrained ~lo:0x80 ~hi:0x9f ~bad:Gate_core.Surrogate ~more:1 tl
    | () when b <= 0xef ->
      constrained ~lo:0x80 ~hi:0xbf ~bad:Gate_core.Bad_byte ~more:1 tl
    | () when b = 0xf0 ->
      constrained ~lo:0x90 ~hi:0xbf ~bad:Gate_core.Overlong ~more:2 tl
    | () when b <= 0xf3 ->
      constrained ~lo:0x80 ~hi:0xbf ~bad:Gate_core.Bad_byte ~more:2 tl
    | () when b = 0xf4 ->
      constrained ~lo:0x80 ~hi:0x8f ~bad:Gate_core.Out_of_range ~more:2 tl
    | () when b <= 0xfd -> Error Gate_core.Out_of_range
    | () -> Error Gate_core.Bad_byte
  (* The lead-specific second byte: inside [lo, hi] the sequence goes on
     to [more] generic continuations; inside the continuation range but
     outside [lo, hi] the lead's [bad] reason fires; anything else is a
     plain bad byte. *)
  and constrained ~lo ~hi ~bad ~more tl =
    match tl with
    | [] -> Error Gate_core.Truncated
    | c :: tl' ->
      let b = Char.code c in
      (match () with
       | () when lo <= b && b <= hi -> conts more tl'
       | () when cont b -> Error bad
       | () -> Error Gate_core.Bad_byte)
  and conts n tl =
    match () with
    | () when n <= 0 -> go tl
    | () -> (
      match tl with
      | [] -> Error Gate_core.Truncated
      | c :: tl' -> (
        match () with
        | () when cont (Char.code c) -> conts (n - 1) tl'
        | () -> Error Gate_core.Bad_byte))
  in
  go (List.of_seq (String.to_seq s))
