(* M9 gate: decode/encode roundtrips over every constructor and every
   header-family boundary, canonical byte pins for each family, and
   normalization pins (non-minimal input re-encodes minimal). One line
   per check, exit 1 on FAIL. *)

open Scrubline

(* Roundtrip through the decoder; polymorphic equality is sound here
   because every float check goes through [rtf] instead. *)
let rt (name : string) (v : Msgpack.t) : string * bool =
  ( name,
    Msgpack.decode (Msgpack.encode v)
    |> Result.fold
         ~ok:(fun got -> got = v)
         ~error:(fun (_ : Msgpack.error) -> false) )

(* Float roundtrip, bit-exact: nan and the 0.0 signs compare by bits. *)
let rtf (name : string) (f : float) : string * bool =
  ( name,
    Msgpack.decode (Msgpack.encode (Msgpack.Float f))
    |> Result.fold
         ~ok:(fun got ->
           match got with
           | Msgpack.Float g ->
             Int64.equal (Int64.bits_of_float g) (Int64.bits_of_float f)
           | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _
           | Msgpack.Uint64_edge _ | Msgpack.Str _ | Msgpack.Bin _
           | Msgpack.Arr _ | Msgpack.Map _ | Msgpack.Ext _ -> false)
         ~error:(fun (_ : Msgpack.error) -> false) )

(* Canonical byte pin. *)
let enc (name : string) (v : Msgpack.t) (want : string) : string * bool =
  (name, String.equal (Msgpack.encode v) want)

(* Non-minimal input normalizes on the way back out. *)
let norm (name : string) (bytes : string) (want : string) : string * bool =
  ( name,
    Msgpack.decode bytes
    |> Result.fold
         ~ok:(fun v -> String.equal (Msgpack.encode v) want)
         ~error:(fun (_ : Msgpack.error) -> false) )

let edge_lo : string = "\x40\x00\x00\x00\x00\x00\x00\x00"

let edge_hi : string = "\xff\xff\xff\xff\xff\xff\xff\xff"

let event_time : string = "\x01\x02\x03\x04\x05\x06\x07\x08"

(* Depth 31 of nested arrays: one under the decoder's cap of 32. *)
let deep : Msgpack.t =
  List.fold_left
    (fun acc (_ : int) -> Msgpack.Arr [ acc ])
    (Msgpack.Int 7) (List.init 31 Fun.id)

let checks : (string * bool) list =
  [ rt "nil" Msgpack.Nil;
    rt "false" (Msgpack.Bool false);
    rt "true" (Msgpack.Bool true);
    (* int families, both directions of every boundary *)
    rt "zero" (Msgpack.Int 0);
    rt "fixint top" (Msgpack.Int 127);
    rt "uint8 floor" (Msgpack.Int 128);
    rt "uint8 top" (Msgpack.Int 255);
    rt "uint16 floor" (Msgpack.Int 256);
    rt "uint16 top" (Msgpack.Int 65535);
    rt "uint32 floor" (Msgpack.Int 65536);
    rt "uint32 top" (Msgpack.Int 0xffffffff);
    rt "uint64 floor" (Msgpack.Int 0x100000000);
    rt "uint64 top of int" (Msgpack.Int max_int);
    rt "negative fixint top" (Msgpack.Int (-1));
    rt "negative fixint floor" (Msgpack.Int (-32));
    rt "int8 ceiling" (Msgpack.Int (-33));
    rt "int8 floor" (Msgpack.Int (-128));
    rt "int16 ceiling" (Msgpack.Int (-129));
    rt "int16 floor" (Msgpack.Int (-32768));
    rt "int32 ceiling" (Msgpack.Int (-32769));
    rt "int32 floor" (Msgpack.Int (-0x80000000));
    rt "int64 ceiling" (Msgpack.Int (-0x80000001));
    rt "int64 ocaml floor" (Msgpack.Int min_int);
    (* the 64-bit edge rides its raw bytes *)
    rt "uint64 edge low" (Msgpack.Uint64_edge edge_lo);
    rt "uint64 edge high" (Msgpack.Uint64_edge edge_hi);
    (* floats, bit-exact *)
    rtf "float zero" 0.0;
    rtf "float negative zero" (-0.0);
    rtf "float three halves" 1.5;
    rtf "float avogadro" 6.02214076e23;
    rtf "float infinity" infinity;
    rtf "float negative infinity" neg_infinity;
    rtf "float nan" nan;
    (* str families *)
    rt "fixstr empty" (Msgpack.Str "");
    rt "fixstr top" (Msgpack.Str (String.make 31 'x'));
    rt "str8 floor" (Msgpack.Str (String.make 32 'x'));
    rt "str8 top" (Msgpack.Str (String.make 255 'x'));
    rt "str16 floor" (Msgpack.Str (String.make 256 'x'));
    rt "str32 floor" (Msgpack.Str (String.make 65536 'x'));
    (* bin families *)
    rt "bin8 empty" (Msgpack.Bin "");
    rt "bin8 top" (Msgpack.Bin (String.make 255 '\x00'));
    rt "bin16 floor" (Msgpack.Bin (String.make 256 '\x00'));
    rt "bin32 floor" (Msgpack.Bin (String.make 65536 '\x00'));
    (* containers *)
    rt "fixarray empty" (Msgpack.Arr []);
    rt "fixarray top" (Msgpack.Arr (List.init 15 (fun i -> Msgpack.Int i)));
    rt "array16 floor" (Msgpack.Arr (List.init 16 (fun i -> Msgpack.Int i)));
    rt "deep nesting under the cap" deep;
    rt "fixmap empty" (Msgpack.Map []);
    rt "fixmap one"
      (Msgpack.Map [ (Msgpack.Str "a", Msgpack.Int 1) ]);
    rt "map16 floor"
      (Msgpack.Map
         (List.init 16 (fun i -> (Msgpack.Int i, Msgpack.Int (2 * i)))));
    rt "map key order preserved"
      (Msgpack.Map
         [ (Msgpack.Str "b", Msgpack.Int 1); (Msgpack.Str "a", Msgpack.Int 2) ]);
    rt "mixed record"
      (Msgpack.Map
         [ (Msgpack.Str "log", Msgpack.Str "msg");
           (Msgpack.Str "n", Msgpack.Int 42);
           ( Msgpack.Str "arr",
             Msgpack.Arr [ Msgpack.Nil; Msgpack.Bool true; Msgpack.Bin "\x00" ]
           );
           (Msgpack.Str "et", Msgpack.Ext (0, event_time)) ]);
    (* ext: every fixext size, both ext8 shapes, ext16, signed types *)
    rt "ext8 empty" (Msgpack.Ext (1, ""));
    rt "fixext1" (Msgpack.Ext (2, "\x0a"));
    rt "fixext2" (Msgpack.Ext (3, "\x0a\x0b"));
    rt "fixext4" (Msgpack.Ext (4, "\x0a\x0b\x0c\x0d"));
    rt "fixext8 event time" (Msgpack.Ext (0, event_time));
    rt "fixext16" (Msgpack.Ext (5, String.make 16 'q'));
    rt "ext8 odd length" (Msgpack.Ext (6, "\x01\x02\x03"));
    rt "ext8 seventeen" (Msgpack.Ext (7, String.make 17 'r'));
    rt "ext8 top" (Msgpack.Ext (8, String.make 255 's'));
    rt "ext16 floor" (Msgpack.Ext (9, String.make 256 't'));
    rt "ext negative type" (Msgpack.Ext (-1, "\x00\x01\x02"));
    rt "ext type floor" (Msgpack.Ext (-128, "\x77"));
    rt "ext type top" (Msgpack.Ext (127, "\x77"));
    (* canonical byte pins, one per header family *)
    enc "pin nil" Msgpack.Nil "\xc0";
    enc "pin false" (Msgpack.Bool false) "\xc2";
    enc "pin true" (Msgpack.Bool true) "\xc3";
    enc "pin fixint" (Msgpack.Int 1) "\x01";
    enc "pin negative fixint" (Msgpack.Int (-1)) "\xff";
    enc "pin uint8" (Msgpack.Int 128) "\xcc\x80";
    enc "pin uint16" (Msgpack.Int 256) "\xcd\x01\x00";
    enc "pin uint32" (Msgpack.Int 65536) "\xce\x00\x01\x00\x00";
    enc "pin uint64"
      (Msgpack.Int 0x100000000)
      "\xcf\x00\x00\x00\x01\x00\x00\x00\x00";
    enc "pin int8" (Msgpack.Int (-33)) "\xd0\xdf";
    enc "pin int16" (Msgpack.Int (-129)) "\xd1\xff\x7f";
    enc "pin int32" (Msgpack.Int (-32769)) "\xd2\xff\xff\x7f\xff";
    enc "pin int64"
      (Msgpack.Int (-0x80000001))
      "\xd3\xff\xff\xff\xff\x7f\xff\xff\xff";
    enc "pin int64 ocaml floor" (Msgpack.Int min_int)
      "\xd3\xc0\x00\x00\x00\x00\x00\x00\x00";
    enc "pin uint64 edge" (Msgpack.Uint64_edge edge_lo) ("\xcf" ^ edge_lo);
    enc "pin float one" (Msgpack.Float 1.0)
      "\xcb\x3f\xf0\x00\x00\x00\x00\x00\x00";
    enc "pin fixstr" (Msgpack.Str "hi") "\xa2hi";
    enc "pin str8"
      (Msgpack.Str (String.make 32 'x'))
      ("\xd9\x20" ^ String.make 32 'x');
    enc "pin bin8" (Msgpack.Bin "") "\xc4\x00";
    enc "pin fixarray"
      (Msgpack.Arr [ Msgpack.Int 1; Msgpack.Int 2 ])
      "\x92\x01\x02";
    enc "pin fixmap"
      (Msgpack.Map [ (Msgpack.Str "a", Msgpack.Int 1) ])
      "\x81\xa1a\x01";
    enc "pin fixext8 event time" (Msgpack.Ext (0, event_time))
      ("\xd7\x00" ^ event_time);
    enc "pin ext8 negative type"
      (Msgpack.Ext (-1, "\x00\x01\x02"))
      "\xc7\x03\xff\x00\x01\x02";
    (* non-minimal input normalizes *)
    norm "uint16 one normalizes to fixint" "\xcd\x00\x01" "\x01";
    norm "int64 minus one normalizes to fixint"
      "\xd3\xff\xff\xff\xff\xff\xff\xff\xff" "\xff";
    norm "str8 empty normalizes to fixstr" "\xd9\x00" "\xa0"
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
  | 0 -> print_endline "test_encode: PASS"
  | _ ->
    print_endline "test_encode: FAIL";
    exit 1
