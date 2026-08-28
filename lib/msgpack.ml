(* M7+M8: msgpack decode over the Reader cursor. Every lead byte is a
   compile-checked case: scalars (nil, bool, the int families with their
   64-bit edges, float32/float64 bit-exact), str/bin payloads, and the
   containers (fixarray/array16/32, fixmap/map16/32, ext/fixext). The
   only unclaimed lead is 0xc1, which the spec reserves.

   Caps, each checked before any allocation or element decode:
   - str, bin, and ext payloads: Caps.string_max
   - array and map element counts: Caps.entries_max
   - container nesting: Caps.depth_max
   Duplicate map keys (structural equality) are a typed reject, keyed to
   the offset of the second key's lead byte.

   64-bit edges (OCaml's int is 63-bit, max_int = 2^62 - 1):
   - uint64 above max_int rides [Uint64_edge] with the raw 8 big-endian
     bytes, opaque and never arithmetic (DESIGN section 5).
   - int64 in [2^62, 2^63) is byte-identical to its unsigned view and
     rides [Uint64_edge] the same way.
   - int64 below -2^62 is the typed reject [Int64_negative_edge]: the
     gate dead-letters it rather than rounding.
   - int64 with the top two bits set fits: the value is
     low62 + min_int, computed without an overflowing shift.

   The ext type byte is signed (i8); EventTime arrives as fixext8 type 0
   and decodes to [Ext (0, bytes)], which forward.ml (M10) interprets. *)

type t =
  | Nil
  | Bool of bool
  | Int of int
  | Uint64_edge of string
  | Float of float
  | Str of string
  | Bin of string
  | Arr of t list
  | Map of (t * t) list
  | Ext of int * string

type error =
  | Reserved_lead of { at : int }
  | Truncated of { need : int; have : int; at : int }
  | Negative_count of { count : int; at : int }
  | Str_over of { len : int; at : int }
  | Count_over of { count : int; at : int }
  | Depth_over of { at : int }
  | Duplicate_key of { at : int }
  | Int64_negative_edge of { at : int }
  | Trailing of { extra : int }

let error_to_string (e : error) : string =
  match e with
  | Reserved_lead { at } -> Printf.sprintf "reserved lead 0xc1 at byte %d" at
  | Truncated { need; have; at } ->
    Printf.sprintf "truncated: need %d, have %d, at byte %d" need have at
  | Negative_count { count; at } ->
    Printf.sprintf "negative count %d at byte %d" count at
  | Str_over { len; at } ->
    Printf.sprintf "payload of %d bytes over cap at byte %d" len at
  | Count_over { count; at } ->
    Printf.sprintf "%d entries over cap at byte %d" count at
  | Depth_over { at } -> Printf.sprintf "nesting over cap at byte %d" at
  | Duplicate_key { at } -> Printf.sprintf "duplicate map key at byte %d" at
  | Int64_negative_edge { at } ->
    Printf.sprintf "int64 below -2^62 at byte %d" at
  | Trailing { extra } -> Printf.sprintf "%d trailing bytes" extra

let of_reader_error (e : Reader.error) : error =
  match e with
  | Reader.Truncated { need; have; at } -> Truncated { need; have; at }
  | Reader.Negative_count { count; at } -> Negative_count { count; at }

(* [len] came from an unsigned read, so it is nonnegative. [at] is the
   lead byte's offset, which names the value the error belongs to. *)
let str_payload (len : int) (at : int) (r : Reader.t)
    (wrap : string -> t) : (t * Reader.t, error) result =
  match () with
  | () when len > Caps.string_max -> Error (Str_over { len; at })
  | () ->
    Reader.take_string len r
    |> Result.map_error of_reader_error
    |> Result.map (fun (s, r') -> (wrap s, r'))

(* IEEE bit assembly; Int64 here is bit transport for float_of_bits, not
   value arithmetic. *)
let bits64 (chunk : char list) : int64 =
  List.fold_left
    (fun acc c ->
      Int64.logor (Int64.shift_left acc 8) (Int64.of_int (Char.code c)))
    0L chunk

(* The d3 cases by the top two bits of the first byte; [chunk] is the 8
   bytes a successful take produced, so the [] arm is dead but honest. *)
let int64_scalar (chunk : char list) (at : int) : (t, error) result =
  match chunk with
  | [] -> Error (Truncated { need = 8; have = 0; at })
  | c :: rest ->
    let b0 = Char.code c in
    let low62 = ((b0 land 0x3f) lsl 56) lor Reader.fold_be rest in
    (match () with
     | () when b0 < 0x40 -> Ok (Int low62)
     | () when b0 < 0x80 -> Ok (Uint64_edge (Reader.string_of_chars chunk))
     | () when b0 < 0xc0 -> Error (Int64_negative_edge { at })
     | () -> Ok (Int (low62 + min_int)))

let rec value (depth : int) (r0 : Reader.t) : (t * Reader.t, error) result =
  let at = Reader.offset r0 in
  match () with
  | () when depth > Caps.depth_max -> Error (Depth_over { at })
  | () ->
    Result.bind
      (Reader.byte r0 |> Result.map_error of_reader_error)
      (fun (b, r) ->
        let rd read wrap =
          read r
          |> Result.map_error of_reader_error
          |> Result.map (fun (v, r') -> (wrap v, r'))
        in
        let len_then read wrap =
          Result.bind
            (read r |> Result.map_error of_reader_error)
            (fun (len, r') -> str_payload len at r' wrap)
        in
        let items read build =
          Result.bind
            (read r |> Result.map_error of_reader_error)
            (fun (n, r') -> build depth n at r')
        in
        match () with
        | () when b <= 0x7f -> Ok (Int b, r)
        | () when b <= 0x8f -> map_items depth (b land 0x0f) at r
        | () when b <= 0x9f -> array_items depth (b land 0x0f) at r
        | () when b <= 0xbf -> str_payload (b land 0x1f) at r (fun s -> Str s)
        | () when b = 0xc0 -> Ok (Nil, r)
        | () when b = 0xc1 -> Error (Reserved_lead { at })
        | () when b = 0xc2 -> Ok (Bool false, r)
        | () when b = 0xc3 -> Ok (Bool true, r)
        | () when b = 0xc4 -> len_then Reader.byte (fun s -> Bin s)
        | () when b = 0xc5 -> len_then Reader.u16be (fun s -> Bin s)
        | () when b = 0xc6 -> len_then Reader.u32be (fun s -> Bin s)
        | () when b = 0xc7 -> items Reader.byte ext_payload
        | () when b = 0xc8 -> items Reader.u16be ext_payload
        | () when b = 0xc9 -> items Reader.u32be ext_payload
        | () when b = 0xca ->
          rd Reader.u32be (fun v ->
            Float (Int32.float_of_bits (Int32.of_int v)))
        | () when b = 0xcb ->
          Reader.take 8 r
          |> Result.map_error of_reader_error
          |> Result.map (fun (chunk, r') ->
            (Float (Int64.float_of_bits (bits64 chunk)), r'))
        | () when b = 0xcc -> rd Reader.byte (fun v -> Int v)
        | () when b = 0xcd -> rd Reader.u16be (fun v -> Int v)
        | () when b = 0xce -> rd Reader.u32be (fun v -> Int v)
        | () when b = 0xcf ->
          Reader.u64be r
          |> Result.map_error of_reader_error
          |> Result.map (fun (u, r') ->
            match u with
            | Reader.U64 n -> (Int n, r')
            | Reader.U64_edge raw -> (Uint64_edge raw, r'))
        | () when b = 0xd0 ->
          rd Reader.byte (fun v ->
            Int (match () with () when v >= 0x80 -> v - 0x100 | () -> v))
        | () when b = 0xd1 ->
          rd Reader.u16be (fun v ->
            Int (match () with () when v >= 0x8000 -> v - 0x10000 | () -> v))
        | () when b = 0xd2 ->
          rd Reader.u32be (fun v ->
            Int
              (match () with
              | () when v >= 0x80000000 -> v - 0x100000000
              | () -> v))
        | () when b = 0xd3 ->
          Result.bind
            (Reader.take 8 r |> Result.map_error of_reader_error)
            (fun (chunk, r') ->
              int64_scalar chunk at |> Result.map (fun v -> (v, r')))
        | () when b = 0xd4 -> ext_payload depth 1 at r
        | () when b = 0xd5 -> ext_payload depth 2 at r
        | () when b = 0xd6 -> ext_payload depth 4 at r
        | () when b = 0xd7 -> ext_payload depth 8 at r
        | () when b = 0xd8 -> ext_payload depth 16 at r
        | () when b = 0xd9 -> len_then Reader.byte (fun s -> Str s)
        | () when b = 0xda -> len_then Reader.u16be (fun s -> Str s)
        | () when b = 0xdb -> len_then Reader.u32be (fun s -> Str s)
        | () when b = 0xdc -> items Reader.u16be array_items
        | () when b = 0xdd -> items Reader.u32be array_items
        | () when b = 0xde -> items Reader.u16be map_items
        | () when b = 0xdf -> items Reader.u32be map_items
        | () -> Ok (Int (b - 0x100), r))

and array_items (depth : int) (n : int) (at : int) (r : Reader.t) :
    (t * Reader.t, error) result =
  match () with
  | () when n > Caps.entries_max -> Error (Count_over { count = n; at })
  | () ->
    let rec go k acc r =
      match () with
      | () when k <= 0 -> Ok (Arr (List.rev acc), r)
      | () ->
        Result.bind (value (depth + 1) r) (fun (v, r') ->
          go (k - 1) (v :: acc) r')
    in
    go n [] r

and map_items (depth : int) (n : int) (at : int) (r : Reader.t) :
    (t * Reader.t, error) result =
  match () with
  | () when n > Caps.entries_max -> Error (Count_over { count = n; at })
  | () ->
    let rec go k acc r =
      match () with
      | () when k <= 0 -> Ok (Map (List.rev acc), r)
      | () ->
        let key_at = Reader.offset r in
        Result.bind (value (depth + 1) r) (fun (key, r1) ->
          match () with
          | () when List.exists (fun (k0, _) -> k0 = key) acc ->
            Error (Duplicate_key { at = key_at })
          | () ->
            Result.bind (value (depth + 1) r1) (fun (v, r2) ->
              go (k - 1) ((key, v) :: acc) r2))
    in
    go n [] r

(* Ext: signed type byte, then [n] data bytes, sharing the string cap.
   [depth] is unused (ext is a leaf) but keeps the four builders one
   shape for [items]. *)
and ext_payload (depth : int) (n : int) (at : int) (r : Reader.t) :
    (t * Reader.t, error) result =
  ignore depth;
  match () with
  | () when n > Caps.string_max -> Error (Str_over { len = n; at })
  | () ->
    Result.bind
      (Reader.byte r |> Result.map_error of_reader_error)
      (fun (tb, r1) ->
        let ty = match () with () when tb >= 0x80 -> tb - 0x100 | () -> tb in
        Reader.take_string n r1
        |> Result.map_error of_reader_error
        |> Result.map (fun (data, r2) -> (Ext (ty, data), r2)))

let decode_one (r : Reader.t) : (t * Reader.t, error) result = value 0 r

(* One complete value filling the whole buffer; forward frames stream
   [decode_one] instead. *)
let decode (s : string) : (t, error) result =
  Result.bind (decode_one (Reader.of_string s)) (fun (v, r) ->
    match () with
    | () when Reader.remaining r = 0 -> Ok v
    | () -> Error (Trailing { extra = Reader.remaining r }))
