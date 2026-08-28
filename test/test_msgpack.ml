(* M7+M8 gate: scalar fixtures (one per format-family arm and per 64-bit
   edge), container fixtures (arrays, maps, ext, the caps, duplicate
   keys), and the typed rejects. One line per check, exit 1 on FAIL. *)

open Scrubline

let is_v (v : Msgpack.t) (s : string) : bool =
  Result.fold ~ok:(fun got -> got = v)
    ~error:(fun (_ : Msgpack.error) -> false)
    (Msgpack.decode s)

let errs (e : Msgpack.error) (s : string) : bool =
  Result.fold
    ~ok:(fun (_ : Msgpack.t) -> false)
    ~error:(fun got -> got = e)
    (Msgpack.decode s)

let checks : (string * bool) list =
  [
    ("nil", is_v Msgpack.Nil "\xc0");
    ("false", is_v (Msgpack.Bool false) "\xc2");
    ("true", is_v (Msgpack.Bool true) "\xc3");
    (* int families *)
    ("fixint zero", is_v (Msgpack.Int 0) "\x00");
    ("fixint top", is_v (Msgpack.Int 127) "\x7f");
    ("negative fixint floor", is_v (Msgpack.Int (-32)) "\xe0");
    ("negative fixint top", is_v (Msgpack.Int (-1)) "\xff");
    ("uint8", is_v (Msgpack.Int 255) "\xcc\xff");
    ("uint16", is_v (Msgpack.Int 0x1234) "\xcd\x12\x34");
    ("uint32 max", is_v (Msgpack.Int 0xffffffff) "\xce\xff\xff\xff\xff");
    ("uint64 small", is_v (Msgpack.Int 42) "\xcf\x00\x00\x00\x00\x00\x00\x00\x2a");
    ( "uint64 top of int",
      is_v (Msgpack.Int max_int) "\xcf\x3f\xff\xff\xff\xff\xff\xff\xff" );
    ( "uint64 edge",
      is_v
        (Msgpack.Uint64_edge "\x40\x00\x00\x00\x00\x00\x00\x00")
        "\xcf\x40\x00\x00\x00\x00\x00\x00\x00" );
    ( "uint64 all ones is the edge",
      is_v
        (Msgpack.Uint64_edge "\xff\xff\xff\xff\xff\xff\xff\xff")
        "\xcf\xff\xff\xff\xff\xff\xff\xff\xff" );
    ("int8 top", is_v (Msgpack.Int 127) "\xd0\x7f");
    ("int8 floor", is_v (Msgpack.Int (-128)) "\xd0\x80");
    ("int16 floor", is_v (Msgpack.Int (-32768)) "\xd1\x80\x00");
    ("int16 top", is_v (Msgpack.Int 32767) "\xd1\x7f\xff");
    ("int32 minus one", is_v (Msgpack.Int (-1)) "\xd2\xff\xff\xff\xff");
    ("int32 floor", is_v (Msgpack.Int (-2147483648)) "\xd2\x80\x00\x00\x00");
    ("int32 top", is_v (Msgpack.Int 2147483647) "\xd2\x7f\xff\xff\xff");
    ("int64 small", is_v (Msgpack.Int 42) "\xd3\x00\x00\x00\x00\x00\x00\x00\x2a");
    ( "int64 minus one",
      is_v (Msgpack.Int (-1)) "\xd3\xff\xff\xff\xff\xff\xff\xff\xff" );
    ( "int64 minus two",
      is_v (Msgpack.Int (-2)) "\xd3\xff\xff\xff\xff\xff\xff\xff\xfe" );
    ( "int64 ocaml floor",
      is_v (Msgpack.Int min_int) "\xd3\xc0\x00\x00\x00\x00\x00\x00\x00" );
    ( "int64 positive edge rides uint64",
      is_v
        (Msgpack.Uint64_edge "\x40\x00\x00\x00\x00\x00\x00\x00")
        "\xd3\x40\x00\x00\x00\x00\x00\x00\x00" );
    ( "int64 negative edge floor rejects",
      errs (Msgpack.Int64_negative_edge { at = 0 })
        "\xd3\x80\x00\x00\x00\x00\x00\x00\x00" );
    ( "int64 negative edge ceiling rejects",
      errs (Msgpack.Int64_negative_edge { at = 0 })
        "\xd3\xbf\xff\xff\xff\xff\xff\xff\xff" );
    (* floats, bit-exact *)
    ("float32 one", is_v (Msgpack.Float 1.0) "\xca\x3f\x80\x00\x00");
    ("float32 negative", is_v (Msgpack.Float (-1.5)) "\xca\xbf\xc0\x00\x00");
    ( "float64 three halves",
      is_v (Msgpack.Float 1.5) "\xcb\x3f\xf8\x00\x00\x00\x00\x00\x00" );
    ( "float64 negative",
      is_v (Msgpack.Float (-2.25)) "\xcb\xc0\x02\x00\x00\x00\x00\x00\x00" );
    ( "float64 zero",
      is_v (Msgpack.Float 0.0) "\xcb\x00\x00\x00\x00\x00\x00\x00\x00" );
    (* str and bin *)
    ("fixstr empty", is_v (Msgpack.Str "") "\xa0");
    ("fixstr", is_v (Msgpack.Str "abc") "\xa3abc");
    ( "fixstr length above the low nibble",
      is_v (Msgpack.Str "abcdefghijklmnopq") "\xb1abcdefghijklmnopq" );
    ("str8", is_v (Msgpack.Str "abc") "\xd9\x03abc");
    ("str16", is_v (Msgpack.Str "abc") "\xda\x00\x03abc");
    ("str32", is_v (Msgpack.Str "abc") "\xdb\x00\x00\x00\x03abc");
    ("bin8", is_v (Msgpack.Bin "\x00\xff") "\xc4\x02\x00\xff");
    ("bin16", is_v (Msgpack.Bin "A") "\xc5\x00\x01A");
    ("bin32", is_v (Msgpack.Bin "B") "\xc6\x00\x00\x00\x01B");
    ( "str32 over cap fails before the take",
      errs (Msgpack.Str_over { len = 0x40001; at = 0 }) "\xdb\x00\x04\x00\x01" );
    ( "bin32 shares the cap",
      errs (Msgpack.Str_over { len = 0x40001; at = 0 }) "\xc6\x00\x04\x00\x01" );
    (* containers: arrays *)
    ("fixarray empty", is_v (Msgpack.Arr []) "\x90");
    ( "fixarray two ints",
      is_v (Msgpack.Arr [ Msgpack.Int 1; Msgpack.Int 2 ]) "\x92\x01\x02" );
    ( "array16",
      is_v
        (Msgpack.Arr [ Msgpack.Int 1; Msgpack.Int 2; Msgpack.Int 3 ])
        "\xdc\x00\x03\x01\x02\x03" );
    ("array32", is_v (Msgpack.Arr [ Msgpack.Nil ]) "\xdd\x00\x00\x00\x01\xc0");
    ( "nested arrays",
      is_v (Msgpack.Arr [ Msgpack.Arr [ Msgpack.Nil ] ]) "\x91\x91\xc0" );
    (* containers: maps *)
    ("fixmap empty", is_v (Msgpack.Map []) "\x80");
    ( "fixmap one pair",
      is_v (Msgpack.Map [ (Msgpack.Str "a", Msgpack.Int 1) ]) "\x81\xa1a\x01" );
    ( "map16",
      is_v
        (Msgpack.Map [ (Msgpack.Str "k", Msgpack.Bool true) ])
        "\xde\x00\x01\xa1k\xc3" );
    ( "map32",
      is_v
        (Msgpack.Map [ (Msgpack.Int 1, Msgpack.Int 2) ])
        "\xdf\x00\x00\x00\x01\x01\x02" );
    ( "map key order preserved",
      is_v
        (Msgpack.Map
           [ (Msgpack.Str "b", Msgpack.Int 1); (Msgpack.Str "a", Msgpack.Int 2) ])
        "\x82\xa1b\x01\xa1a\x02" );
    ( "duplicate key rejected at the second key",
      errs (Msgpack.Duplicate_key { at = 4 }) "\x82\xa1a\x01\xa1a\x02" );
    (* depth and count caps *)
    ( "nesting to the cap decodes",
      Result.fold
        ~ok:(fun (_ : Msgpack.t) -> true)
        ~error:(fun (_ : Msgpack.error) -> false)
        (Msgpack.decode
           (String.concat "" (List.init 32 (fun (_ : int) -> "\x91")) ^ "\xc0"))
    );
    ( "nesting past the cap rejects",
      errs
        (Msgpack.Depth_over { at = 33 })
        (String.concat "" (List.init 33 (fun (_ : int) -> "\x91")) ^ "\xc0") );
    ( "array count over cap",
      errs (Msgpack.Count_over { count = 8193; at = 0 }) "\xdd\x00\x00\x20\x01" );
    ( "map count over cap",
      errs (Msgpack.Count_over { count = 8193; at = 0 }) "\xdf\x00\x00\x20\x01" );
    (* ext *)
    ("fixext1", is_v (Msgpack.Ext (1, "\xff")) "\xd4\x01\xff");
    ( "fixext8 type 0 is the EventTime shape",
      is_v
        (Msgpack.Ext (0, "\x00\x00\x00\x01\x00\x00\x00\x02"))
        "\xd7\x00\x00\x00\x00\x01\x00\x00\x00\x02" );
    ( "fixext16",
      is_v (Msgpack.Ext (5, "0123456789abcdef")) "\xd8\x050123456789abcdef" );
    ("ext8", is_v (Msgpack.Ext (2, "abc")) "\xc7\x03\x02abc");
    ("ext8 empty", is_v (Msgpack.Ext (10, "")) "\xc7\x00\x0a");
    ("ext16", is_v (Msgpack.Ext (127, "Z")) "\xc8\x00\x01\x7fZ");
    ("ext32", is_v (Msgpack.Ext (0, "A")) "\xc9\x00\x00\x00\x01\x00A");
    ("ext negative type", is_v (Msgpack.Ext (-1, "\x00")) "\xd4\xff\x00");
    ( "ext payload shares the cap",
      errs (Msgpack.Str_over { len = 0x40001; at = 0 }) "\xc9\x00\x04\x00\x01" );
    (* typed rejects *)
    ("reserved c1", errs (Msgpack.Reserved_lead { at = 0 }) "\xc1");
    ( "uint16 truncated",
      errs (Msgpack.Truncated { need = 2; have = 1; at = 1 }) "\xcd\x12" );
    ( "str8 payload truncated",
      errs (Msgpack.Truncated { need = 5; have = 2; at = 2 }) "\xd9\x05ab" );
    ( "empty input truncated",
      errs (Msgpack.Truncated { need = 1; have = 0; at = 0 }) "" );
    ( "array element truncated",
      errs (Msgpack.Truncated { need = 1; have = 0; at = 2 }) "\x92\x01" );
    ( "fixext type byte truncated",
      errs (Msgpack.Truncated { need = 1; have = 0; at = 1 }) "\xd4" );
    ("trailing bytes named", errs (Msgpack.Trailing { extra = 1 }) "\xc0\xc0");
    ( "decode_one leaves the tail",
      Msgpack.decode_one (Reader.of_string "\xc0XY")
      |> Result.fold
           ~ok:(fun (v, r) -> v = Msgpack.Nil && Reader.remaining r = 2)
           ~error:(fun (_ : Msgpack.error) -> false) );
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
  | 0 -> print_endline "test_msgpack: PASS"
  | _ ->
    print_endline "test_msgpack: FAIL";
    exit 1
