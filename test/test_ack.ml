(* M11: ack tests off the same real fluent-bit 5.1.1 captures as
   test_forward.ml (provenance comments there).
   cap_forward_ack: -p require_ack_response=true -- arity-3 Forward
   frame whose option map (chunk, size, fluent_signal) uses a
   NON-MINIMAL map32 header straight off the wire.
   cap_forward_int_time: -p time_as_integer=true -- arity-2 frame
   with no options element at all. *)

open Scrubline

let shape : Err.t = Err.Malformed Gate_core.Bad_frame_shape

let cap_forward_ack : string =
   "\x93\xa7\x61\x70\x70\x2e\x6c\x6f\x67\x91\x92\x92\xd7\x00\x6a\x91" ^
   "\x2d\x46\x06\x47\x5c\x60\x80\x82\xa3\x6c\x6f\x67\xd9\x20\x70\x61" ^
   "\x79\x6d\x65\x6e\x74\x20\x6f\x6b\x20\x63\x61\x72\x64\x3d\x34\x31" ^
   "\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\xa6\x73" ^
   "\x74\x72\x65\x61\x6d\xa6\x73\x74\x64\x65\x72\x72\xdf\x00\x00\x00" ^
   "\x03\xa5\x63\x68\x75\x6e\x6b\xb8\x75\x49\x4f\x45\x39\x59\x74\x66" ^
   "\x39\x56\x6b\x46\x79\x7a\x47\x76\x54\x30\x46\x42\x37\x51\x3d\x3d" ^
   "\xa4\x73\x69\x7a\x65\x01\xad\x66\x6c\x75\x65\x6e\x74\x5f\x73\x69" ^
   "\x67\x6e\x61\x6c\x00"

let cap_forward_int_time : string =
   "\x92\xa7\x61\x70\x70\x2e\x6c\x6f\x67\x91\x92\xce\x6a\x91\x2d\x4d" ^
   "\x82\xa3\x6c\x6f\x67\xd9\x20\x70\x61\x79\x6d\x65\x6e\x74\x20\x6f" ^
   "\x6b\x20\x63\x61\x72\x64\x3d\x34\x31\x31\x31\x31\x31\x31\x31\x31" ^
   "\x31\x31\x31\x31\x31\x31\x31\xa6\x73\x74\x72\x65\x61\x6d\xa6\x73" ^
   "\x74\x64\x65\x72\x72"

(* The capture's chunk id: 24 base64 chars. *)
let cap_chunk : string = "uIOE9Ytf9VkFyzGvT0FB7Q=="

let enc : Msgpack.t -> string = Msgpack.encode

let chunk_from (s : string) : (string option, Err.t) result =
  Result.bind (Forward.decode s)
    (fun ((_ : Forward.frame), (opts : Forward.options)) -> Ack.chunk_of opts)

let str_opts (v : Msgpack.t) : Forward.options = [ (Msgpack.Str "chunk", v) ]

let checks : (string * bool) list =
  [ ( "capture: chunk parses off the wire options",
      chunk_from cap_forward_ack = Ok (Some cap_chunk) );
    ( "capture: frame without options needs no ack",
      chunk_from cap_forward_int_time = Ok None );
    ( "no chunk key: no ack",
      Ack.chunk_of
        [ (Msgpack.Str "size", Msgpack.Int 1);
          (Msgpack.Str "fluent_signal", Msgpack.Int 0) ]
      = Ok None );
    ("empty options: no ack", Ack.chunk_of [] = Ok None);
    ( "non-str option keys never match chunk",
      Ack.chunk_of [ (Msgpack.Int 1, Msgpack.Str "x") ] = Ok None );
    ("chunk int rejects", Ack.chunk_of (str_opts (Msgpack.Int 3)) = Error shape);
    ( "chunk bin rejects",
      Ack.chunk_of (str_opts (Msgpack.Bin cap_chunk)) = Error shape );
    ("chunk nil rejects", Ack.chunk_of (str_opts Msgpack.Nil) = Error shape);
    ( "chunk empty str rejects",
      Ack.chunk_of (str_opts (Msgpack.Str "")) = Error shape );
    ( "chunk invalid utf-8 names bad_byte",
      Ack.chunk_of (str_opts (Msgpack.Str "\xff"))
      = Error (Err.Bad_utf8 Gate_core.Bad_byte) );
    ( "duplicate chunk keys name duplicate_key",
      Ack.chunk_of
        [ (Msgpack.Str "chunk", Msgpack.Str "a");
          (Msgpack.Str "chunk", Msgpack.Str "a") ]
      = Error (Err.Malformed Gate_core.Duplicate_key) );
    ( "wire duplicate chunk keys reject at decode",
      chunk_from
        (enc
           (Msgpack.Arr
              [ Msgpack.Str "app"; Msgpack.Arr [];
                Msgpack.Map
                  [ (Msgpack.Str "chunk", Msgpack.Str "a");
                    (Msgpack.Str "chunk", Msgpack.Str "b") ] ]))
      = Error (Err.Malformed Gate_core.Duplicate_key) );
    ( "chunk at string_max carries no hidden cap",
      Ack.chunk_of (str_opts (Msgpack.Str (String.make Caps.string_max 'a')))
      = Ok (Some (String.make Caps.string_max 'a')) );
    ( "capture: response bytes pinned",
      Ack.response cap_chunk = "\x81\xa3\x61\x63\x6b\xb8" ^ cap_chunk );
    ( "response str8 header for a 32-char id",
      Ack.response (String.make 32 'a')
      = "\x81\xa3\x61\x63\x6b\xd9\x20" ^ String.make 32 'a' );
    ( "response roundtrips through msgpack decode",
      Msgpack.decode (Ack.response "abc")
      = Ok (Msgpack.Map [ (Msgpack.Str "ack", Msgpack.Str "abc") ]) );
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
  | 0 -> print_endline "test_ack: PASS"
  | _ ->
    print_endline "test_ack: FAIL";
    exit 1
