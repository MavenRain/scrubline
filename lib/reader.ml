(* M5: total byte cursor. Input becomes a char list once (the Der idiom:
   every read consumes from the head), so there is no index arithmetic
   and no partial String access anywhere in the decode path. [off] is
   the count of consumed bytes, kept for error reporting; [len] is the
   input size, so [remaining] is O(1). *)

type t = {
  rest : char list;
  off : int;
  len : int;
}

type error =
  | Truncated of { need : int; have : int; at : int }
  | Negative_count of { count : int; at : int }

let error_to_string (e : error) : string =
  match e with
  | Truncated { need; have; at } ->
    Printf.sprintf "truncated: need %d, have %d, at byte %d" need have at
  | Negative_count { count; at } ->
    Printf.sprintf "negative count %d at byte %d" count at

let of_string (s : string) : t =
  { rest = List.of_seq (String.to_seq s); off = 0; len = String.length s }

let remaining (r : t) : int = r.len - r.off

let offset (r : t) : int = r.off

let string_of_chars (l : char list) : string =
  String.of_seq (List.to_seq l)

let byte (r : t) : (int * t, error) result =
  match r.rest with
  | [] -> Error (Truncated { need = 1; have = 0; at = r.off })
  | c :: tl -> Ok (Char.code c, { r with rest = tl; off = r.off + 1 })

(* The next [n] bytes as a chunk. A negative [n] is a caller bug worth
   naming, not clamping. The inner walk returns None only when the input
   runs out, which the Truncated arm converts with exact counts. *)
let take (n : int) (r : t) : (char list * t, error) result =
  match () with
  | () when n < 0 -> Error (Negative_count { count = n; at = r.off })
  | () ->
    let rec go k acc rest =
      match () with
      | () when k <= 0 -> Some (List.rev acc, rest)
      | () -> (
        match rest with
        | [] -> None
        | c :: tl -> go (k - 1) (c :: acc) tl)
    in
    go n [] r.rest
    |> Option.fold
         ~none:
           (Error (Truncated { need = n; have = remaining r; at = r.off }))
         ~some:(fun (chunk, rest) ->
           Ok (chunk, { r with rest; off = r.off + n }))

let take_string (n : int) (r : t) : (string * t, error) result =
  take n r |> Result.map (fun (chunk, r') -> (string_of_chars chunk, r'))

(* Big-endian accumulation. Callers pass at most 4 bytes ([u16be],
   [u32be]) or a fits-checked 8 ([u64be]), so the shift stays inside
   OCaml's 63-bit int. *)
let fold_be (chunk : char list) : int =
  List.fold_left (fun acc c -> (acc lsl 8) lor Char.code c) 0 chunk

let u16be (r : t) : (int * t, error) result =
  take 2 r |> Result.map (fun (chunk, r') -> (fold_be chunk, r'))

let u32be (r : t) : (int * t, error) result =
  take 4 r |> Result.map (fun (chunk, r') -> (fold_be chunk, r'))

(* A u64 is only sometimes an OCaml int: [max_int] is 2^62 - 1, so a
   value whose top two bits are set falls outside. The edge carries the
   raw 8 big-endian bytes opaquely and is never arithmetic (DESIGN
   section 5); the msgpack layer surfaces it as [Uint64_edge]. *)
type u64 =
  | U64 of int
  | U64_edge of string

let u64be (r : t) : (u64 * t, error) result =
  take 8 r
  |> Result.map (fun (chunk, r') ->
    match chunk with
    | c :: _ when Char.code c < 0x40 -> (U64 (fold_be chunk), r')
    | bytes -> (U64_edge (string_of_chars bytes), r'))
