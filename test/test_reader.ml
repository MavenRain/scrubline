(* M5 gate: the total cursor against exact byte fixtures. Each check is a
   named bool; one line per check, exit 1 on any FAIL (gates.sh matches
   on the word FAIL). *)

open Scrubline

(* A successful read whose value satisfies [f]; any error is a failure. *)
let ok_with (f : 'a * Reader.t -> bool)
    (r : ('a * Reader.t, Reader.error) result) : bool =
  Result.fold ~ok:f ~error:(fun (_ : Reader.error) -> false) r

let is_truncated ~need ~have ~at
    (r : ('a * Reader.t, Reader.error) result) : bool =
  Result.fold
    ~ok:(fun (_ : 'a * Reader.t) -> false)
    ~error:(fun (e : Reader.error) ->
      match e with
      | Reader.Truncated t -> t.need = need && t.have = have && t.at = at
      | Reader.Negative_count _ -> false)
    r

let is_negative ~count
    (r : ('a * Reader.t, Reader.error) result) : bool =
  Result.fold
    ~ok:(fun (_ : 'a * Reader.t) -> false)
    ~error:(fun (e : Reader.error) ->
      match e with
      | Reader.Truncated _ -> false
      | Reader.Negative_count n -> n.count = count)
    r

let is_u64 (v : int) (u : Reader.u64) : bool =
  match u with
  | Reader.U64 n -> n = v
  | Reader.U64_edge _ -> false

let is_edge (raw : string) (u : Reader.u64) : bool =
  match u with
  | Reader.U64 _ -> false
  | Reader.U64_edge s -> String.equal s raw

let checks : (string * bool) list =
  let abc = Reader.of_string "abc" in
  [
    ("fresh cursor: remaining", Reader.remaining abc = 3);
    ("fresh cursor: offset", Reader.offset abc = 0);
    ( "byte consumes one",
      Reader.byte abc
      |> ok_with (fun (b, r) ->
        b = 0x61 && Reader.remaining r = 2 && Reader.offset r = 1) );
    ( "byte on empty is truncated",
      Reader.byte (Reader.of_string "")
      |> is_truncated ~need:1 ~have:0 ~at:0 );
    ( "take exact remainder",
      Reader.take_string 3 abc
      |> ok_with (fun (s, r) -> String.equal s "abc" && Reader.remaining r = 0)
    );
    ( "take beyond end is truncated",
      Reader.take 4 abc |> is_truncated ~need:4 ~have:3 ~at:0 );
    ( "take zero leaves the cursor",
      Reader.take 0 abc
      |> ok_with (fun (chunk, r) ->
        List.length chunk = 0 && Reader.offset r = 0 && Reader.remaining r = 3)
    );
    ("take negative is named", Reader.take (-2) abc |> is_negative ~count:(-2));
    ( "truncation reports the current offset",
      Reader.byte (Reader.of_string "abcd")
      |> ok_with (fun ((_ : int), r) ->
        Reader.take 9 r |> is_truncated ~need:9 ~have:3 ~at:1) );
    ( "u16be is big-endian",
      Reader.u16be (Reader.of_string "\x12\x34")
      |> ok_with (fun (v, r) -> v = 0x1234 && Reader.remaining r = 0) );
    ( "u16be short input is truncated",
      Reader.u16be (Reader.of_string "\x12")
      |> is_truncated ~need:2 ~have:1 ~at:0 );
    ( "u32be is big-endian",
      Reader.u32be (Reader.of_string "\x12\x34\x56\x78\xff")
      |> ok_with (fun (v, r) -> v = 0x12345678 && Reader.remaining r = 1) );
    ( "u64be small value fits",
      Reader.u64be (Reader.of_string "\x00\x00\x00\x00\x00\x00\x00\x2a")
      |> ok_with (fun (u, r) -> is_u64 42 u && Reader.remaining r = 0) );
    ( "u64be byte order",
      Reader.u64be (Reader.of_string "\x00\x01\x02\x03\x04\x05\x06\x07")
      |> ok_with (fun (u, (_ : Reader.t)) -> is_u64 0x0001020304050607 u) );
    ( "u64be top of the int range fits",
      Reader.u64be (Reader.of_string "\x3f\xff\xff\xff\xff\xff\xff\xff")
      |> ok_with (fun (u, (_ : Reader.t)) -> is_u64 max_int u) );
    ( "u64be first value past max_int is the edge",
      Reader.u64be (Reader.of_string "\x40\x00\x00\x00\x00\x00\x00\x00")
      |> ok_with (fun (u, (_ : Reader.t)) ->
        is_edge "\x40\x00\x00\x00\x00\x00\x00\x00" u) );
    ( "u64be all-ones is the edge, raw preserved",
      Reader.u64be (Reader.of_string "\xff\xff\xff\xff\xff\xff\xff\xfe")
      |> ok_with (fun (u, (_ : Reader.t)) ->
        is_edge "\xff\xff\xff\xff\xff\xff\xff\xfe" u) );
    ( "u64be short input is truncated",
      Reader.u64be (Reader.of_string "\x01\x02\x03")
      |> is_truncated ~need:8 ~have:3 ~at:0 );
    ( "mixed reads track the offset",
      Reader.byte (Reader.of_string "\x01\x12\x34rest")
      |> ok_with (fun (b, r) ->
        b = 1
        && (Reader.u16be r
           |> ok_with (fun (v, r2) ->
             v = 0x1234
             && Reader.offset r2 = 3
             && (Reader.take_string (Reader.remaining r2) r2
                |> ok_with (fun (s, r3) ->
                  String.equal s "rest" && Reader.remaining r3 = 0))))) );
    (* Caps pins: DESIGN section 3 values; a drifted constant is a diff
       in two places or it is a FAIL here. *)
    ("caps: frame_max 4 MiB", Caps.frame_max = 4 * 1024 * 1024);
    ("caps: record_max 1 MiB", Caps.record_max = 1024 * 1024);
    ("caps: tag_max", Caps.tag_max = 1024);
    ("caps: depth_max", Caps.depth_max = 32);
    ("caps: entries_max", Caps.entries_max = 8192);
    ("caps: string_max 256 KiB", Caps.string_max = 256 * 1024);
    (* Err bridge: every constructor lands in the same-shaped
       input_class, over the full finite menus from Gate_core. *)
    ( "err: malformed menu maps identity",
      List.for_all
        (fun m ->
          Err.to_input_class (Err.Malformed m) = Gate_core.Malformed m)
        Gate_core.all_malformed );
    ( "err: cap menu maps identity",
      List.for_all
        (fun v ->
          Err.to_input_class (Err.Oversized v) = Gate_core.Oversized v)
        Gate_core.all_caps );
    ( "err: utf8 menu maps identity",
      List.for_all
        (fun u -> Err.to_input_class (Err.Bad_utf8 u) = Gate_core.Bad_utf8 u)
        Gate_core.all_utf8 );
    ( "err: tag rides class_tag",
      List.for_all
        (fun m ->
          String.equal
            (Err.tag (Err.Malformed m))
            ("malformed." ^ Gate_core.malformed_tag m))
        Gate_core.all_malformed );
  ]

let () =
  let failures =
    List.fold_left
      (fun n (name, ok) ->
        Printf.printf "%s %s\n" (if ok then "PASS" else "FAIL") name;
        if ok then n else n + 1)
      0 checks
  in
  match failures with
  | 0 -> print_endline "test_reader: PASS"
  | _ ->
    print_endline "test_reader: FAIL";
    exit 1
