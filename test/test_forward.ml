(* M10 gate: real fluent-bit 5.1.1 wire fixtures plus synthesized
   spec-shape fixtures.  One line per check, exit 1 on FAIL.

   Capture provenance (2026-08-27, fluent-bit 5.1.1 via Homebrew,
   macOS arm64), raw TCP bytes recorded by a local listener:
     fluent-bit -q -f 1 -i dummy -t app.log
       -p 'dummy={"log":...,"stream":"stderr"}' -p rate=2
       -o forward -m '*' -p host=127.0.0.1 -p port=NNN [-p opt]
   cap_forward_v2 / cap_forward_v2_two: default config -- entries wrap
   the time slot as [EventTime, {}] (the fluent-bit v2 event format).
   cap_forward_ack: -p require_ack_response=true -- arity-3 frame whose
   option map (chunk, size, fluent_signal) uses a NON-MINIMAL map32
   header straight off the wire.
   cap_forward_int_time: -p time_as_integer=true -- classic
   [integer-seconds, record] entries. *)

open Scrubline

let shape : Err.t = Err.Malformed Gate_core.Bad_frame_shape

let dec_is (expect : Forward.frame * Forward.options) (s : string) : bool =
  Result.fold
    ~ok:(fun got -> got = expect)
    ~error:(fun (_ : Err.t) -> false)
    (Forward.decode s)

let dec_errs (e : Err.t) (s : string) : bool =
  Result.fold
    ~ok:(fun (_ : Forward.frame * Forward.options) -> false)
    ~error:(fun got -> got = e)
    (Forward.decode s)

let events_of (s : string) : (Forward.event list, Err.t) result =
  Result.bind (Forward.decode s)
    (fun ((f : Forward.frame), (_ : Forward.options)) -> Forward.events f)

let events_are (expect : Forward.event list) (s : string) : bool =
  Result.fold
    ~ok:(fun got -> got = expect)
    ~error:(fun (_ : Err.t) -> false)
    (events_of s)

let events_err (e : Err.t) (s : string) : bool =
  Result.fold
    ~ok:(fun (_ : Forward.event list) -> false)
    ~error:(fun got -> got = e)
    (events_of s)

let cap_forward_v2 : string =
   "\x92\xa7\x61\x70\x70\x2e\x6c\x6f\x67\x91\x92\x92\xd7\x00\x6a\x91" ^
   "\x2d\x02\x1f\x6e\x43\xc0\x80\x82\xa3\x6c\x6f\x67\xd9\x34\x32\x30" ^
   "\x32\x36\x2f\x30\x38\x2f\x32\x37\x20\x31\x32\x3a\x30\x30\x3a\x30" ^
   "\x30\x20\x70\x61\x79\x6d\x65\x6e\x74\x20\x6f\x6b\x20\x63\x61\x72" ^
   "\x64\x3d\x34\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31" ^
   "\x31\x31\xa6\x73\x74\x72\x65\x61\x6d\xa6\x73\x74\x64\x65\x72\x72"

let cap_forward_v2_two : string =
   "\x92\xa7\x61\x70\x70\x2e\x6c\x6f\x67\x92\x92\x92\xd7\x00\x6a\x91" ^
   "\x2d\x04\x01\xa9\x4e\xe8\x80\x82\xa3\x6c\x6f\x67\xd9\x34\x32\x30" ^
   "\x32\x36\x2f\x30\x38\x2f\x32\x37\x20\x31\x32\x3a\x30\x30\x3a\x30" ^
   "\x30\x20\x70\x61\x79\x6d\x65\x6e\x74\x20\x6f\x6b\x20\x63\x61\x72" ^
   "\x64\x3d\x34\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31" ^
   "\x31\x31\xa6\x73\x74\x72\x65\x61\x6d\xa6\x73\x74\x64\x65\x72\x72" ^
   "\x92\x92\xd7\x00\x6a\x91\x2d\x04\x1f\x6e\x4f\x78\x80\x82\xa3\x6c" ^
   "\x6f\x67\xd9\x34\x32\x30\x32\x36\x2f\x30\x38\x2f\x32\x37\x20\x31" ^
   "\x32\x3a\x30\x30\x3a\x30\x30\x20\x70\x61\x79\x6d\x65\x6e\x74\x20" ^
   "\x6f\x6b\x20\x63\x61\x72\x64\x3d\x34\x31\x31\x31\x31\x31\x31\x31" ^
   "\x31\x31\x31\x31\x31\x31\x31\x31\xa6\x73\x74\x72\x65\x61\x6d\xa6" ^
   "\x73\x74\x64\x65\x72\x72"

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

(* Expected views of the captured frames. *)

let cap_record : Forward.record =
  [ ("log", Msgpack.Str "2026/08/27 12:00:00 payment ok card=4111111111111111");
    ("stream", Msgpack.Str "stderr") ]

let cap_short_record : Forward.record =
  [ ("log", Msgpack.Str "payment ok card=4111111111111111");
    ("stream", Msgpack.Str "stderr") ]

let ack_options : Forward.options =
  [ (Msgpack.Str "chunk", Msgpack.Str "uIOE9Ytf9VkFyzGvT0FB7Q==");
    (Msgpack.Str "size", Msgpack.Int 1);
    (Msgpack.Str "fluent_signal", Msgpack.Int 0) ]

(* Synthesized fixture builders: spec shapes fluent-bit does not emit
   (Message, PackedForward, the rejects), built through the M9 encoder
   so only the SHAPE is under test, not header forms -- the captured
   frames pin real header forms. *)

let enc : Msgpack.t -> string = Msgpack.encode
let app : Msgpack.t = Msgpack.Str "app"
let rec_v : Msgpack.t = Msgpack.Map [ (Msgpack.Str "k", Msgpack.Str "v") ]
let rec_t : Forward.record = [ ("k", Msgpack.Str "v") ]
let ev12 : Msgpack.t = Msgpack.Ext (0, "\x00\x00\x00\x01\x00\x00\x00\x02")
let t12 : Forward.time = Forward.Event_time { sec = 1; nsec = 2 }
let tag_cap : string = String.make 1024 'a'
let tag_over : string = String.make 1025 'a'

let entry_int : string = enc (Msgpack.Arr [ Msgpack.Int 3; rec_v ])

let entry_wrapped : string =
  enc (Msgpack.Arr [ Msgpack.Arr [ ev12; Msgpack.Map [] ]; rec_v ])

let packed2 : string = entry_int ^ entry_wrapped

let packed_frame (body_ : Msgpack.t) (rest : Msgpack.t list) : string =
  enc (Msgpack.Arr (app :: body_ :: rest))

let tiny_entry : string = enc (Msgpack.Arr [ Msgpack.Int 0; Msgpack.Map [] ])

let packed_n (n : int) : string =
  String.concat "" (List.init n (fun (_ : int) -> tiny_entry))

let deep_value : Msgpack.t =
  List.fold_left
    (fun v (_ : int) -> Msgpack.Arr [ v ])
    (Msgpack.Int 1)
    (List.init 40 (fun i -> i))

let big_record : Msgpack.t =
  Msgpack.Map
    (List.init 5 (fun i ->
         ( Msgpack.Str ("k" ^ string_of_int i),
           Msgpack.Str (String.make 250_000 'a') )))

(* Review r1: a map whose pair count is over entries_max but whose bytes
   sit far under string_max, so it rides inside a packed body. *)
let wide_map : Msgpack.t =
  Msgpack.Map
    (List.init 8193 (fun i ->
         (Msgpack.Str ("k" ^ string_of_int i), Msgpack.Int 0)))

let checks : (string * bool) list =
  [
    ( "capture: v2 forward frame decodes",
      dec_is
        ( Forward.Forward
            { tag = "app.log";
              entries =
                [ ( Forward.Event_time { sec = 0x6a912d02; nsec = 0x1f6e43c0 },
                    cap_record ) ] },
          [] )
        cap_forward_v2 );
    ( "capture: v2 two-entry frame to events",
      events_are
        [ { Forward.tag = "app.log";
            time = Forward.Event_time { sec = 0x6a912d04; nsec = 0x01a94ee8 };
            record = cap_record };
          { Forward.tag = "app.log";
            time = Forward.Event_time { sec = 0x6a912d04; nsec = 0x1f6e4f78 };
            record = cap_record } ]
        cap_forward_v2_two );
    ( "capture: ack frame carries chunk/size/fluent_signal raw",
      dec_is
        ( Forward.Forward
            { tag = "app.log";
              entries =
                [ ( Forward.Event_time { sec = 0x6a912d46; nsec = 0x06475c60 },
                    cap_short_record ) ] },
          ack_options )
        cap_forward_ack );
    ( "capture: integer-time frame decodes",
      dec_is
        ( Forward.Forward
            { tag = "app.log";
              entries = [ (Forward.Seconds 0x6a912d4d, cap_short_record) ] },
          [] )
        cap_forward_int_time );
    ( "message: integer time",
      dec_is
        ( Forward.Message
            { tag = "app"; time = Forward.Seconds 1_700_000_000; record = rec_t },
          [] )
        (enc (Msgpack.Arr [ app; Msgpack.Int 1_700_000_000; rec_v ])) );
    ( "message: event time plus options",
      dec_is
        ( Forward.Message { tag = "app"; time = t12; record = rec_t },
          [ (Msgpack.Str "chunk", Msgpack.Str "abc") ] )
        (enc
           (Msgpack.Arr
              [ app; ev12; rec_v;
                Msgpack.Map [ (Msgpack.Str "chunk", Msgpack.Str "abc") ] ])) );
    ( "message: negative time rejects",
      dec_errs shape (enc (Msgpack.Arr [ app; Msgpack.Int (-1); rec_v ])) );
    ( "message: float time rejects",
      dec_errs shape (enc (Msgpack.Arr [ app; Msgpack.Float 1.5; rec_v ])) );
    ( "message: u64-edge time rejects, not rounds",
      dec_errs shape
        (enc
           (Msgpack.Arr
              [ app;
                Msgpack.Uint64_edge "\x40\x00\x00\x00\x00\x00\x00\x00";
                rec_v ])) );
    ( "message: ext type 1 rejects",
      dec_errs shape
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Ext (1, "\x00\x00\x00\x01\x00\x00\x00\x02"); rec_v
              ])) );
    ( "message: ext length 4 rejects",
      dec_errs shape
        (enc (Msgpack.Arr [ app; Msgpack.Ext (0, "\x00\x00\x00\x01"); rec_v ]))
    );
    ( "message: nsec 999999999 accepted",
      dec_is
        ( Forward.Message
            { tag = "app";
              time = Forward.Event_time { sec = 0; nsec = 999_999_999 };
              record = rec_t },
          [] )
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Ext (0, "\x00\x00\x00\x00\x3b\x9a\xc9\xff"); rec_v
              ])) );
    ( "message: nsec 10^9 rejects",
      dec_errs shape
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Ext (0, "\x00\x00\x00\x00\x3b\x9a\xca\x00"); rec_v
              ])) );
    ( "message: record not a map rejects",
      dec_errs shape (enc (Msgpack.Arr [ app; Msgpack.Int 0; Msgpack.Str "x" ]))
    );
    ( "message: wrapped time slot is not a message (spec ambiguity)",
      dec_errs shape
        (enc (Msgpack.Arr [ app; Msgpack.Arr [ ev12; Msgpack.Map [] ]; rec_v ]))
    );
    ( "message: events is the singleton",
      events_are
        [ { Forward.tag = "app"; time = Forward.Seconds 7; record = rec_t } ]
        (enc (Msgpack.Arr [ app; Msgpack.Int 7; rec_v ])) );
    ( "forward: bare and wrapped entries mix",
      dec_is
        ( Forward.Forward
            { tag = "app";
              entries = [ (Forward.Seconds 5, rec_t); (t12, rec_t) ] },
          [] )
        (enc
           (Msgpack.Arr
              [ app;
                Msgpack.Arr
                  [ Msgpack.Arr [ Msgpack.Int 5; rec_v ];
                    Msgpack.Arr [ Msgpack.Arr [ ev12; Msgpack.Map [] ]; rec_v ]
                  ] ])) );
    ( "forward: empty entries is zero events",
      events_are [] (enc (Msgpack.Arr [ app; Msgpack.Arr [] ])) );
    ( "forward: non-empty entry metadata rejects",
      dec_errs shape
        (enc
           (Msgpack.Arr
              [ app;
                Msgpack.Arr
                  [ Msgpack.Arr
                      [ Msgpack.Arr
                          [ ev12;
                            Msgpack.Map [ (Msgpack.Str "m", Msgpack.Int 1) ] ];
                        rec_v ] ] ])) );
    ( "forward: entry arity 3 rejects",
      dec_errs shape
        (enc
           (Msgpack.Arr
              [ app;
                Msgpack.Arr [ Msgpack.Arr [ Msgpack.Int 0; rec_v; Msgpack.Nil ] ]
              ])) );
    ( "forward: entry arity 1 rejects",
      dec_errs shape
        (enc
           (Msgpack.Arr [ app; Msgpack.Arr [ Msgpack.Arr [ Msgpack.Int 0 ] ] ]))
    );
    ( "forward: options not a map rejects",
      dec_errs shape (enc (Msgpack.Arr [ app; Msgpack.Arr []; Msgpack.Int 0 ]))
    );
    ( "forward: arity 4 with entries rejects",
      dec_errs shape
        (enc
           (Msgpack.Arr [ app; Msgpack.Arr []; Msgpack.Map []; Msgpack.Map [] ]))
    );
    ( "packed: bin body decodes to the raw envelope",
      dec_is
        (Forward.Packed_forward { tag = "app"; entries_bytes = packed2 }, [])
        (packed_frame (Msgpack.Bin packed2) []) );
    ( "packed: events unpacks both entry forms",
      events_are
        [ { Forward.tag = "app"; time = Forward.Seconds 3; record = rec_t };
          { Forward.tag = "app"; time = t12; record = rec_t } ]
        (packed_frame (Msgpack.Bin packed2) []) );
    ( "packed: str body accepted (compat)",
      dec_is
        (Forward.Packed_forward { tag = "app"; entries_bytes = entry_int }, [])
        (packed_frame (Msgpack.Str entry_int) []) );
    ( "packed: compressed gzip is the typed reject",
      dec_errs
        (Err.Malformed Gate_core.Compressed_unsupported)
        (packed_frame (Msgpack.Bin packed2)
           [ Msgpack.Map [ (Msgpack.Str "compressed", Msgpack.Str "gzip") ] ])
    );
    ( "packed: compressed text accepted",
      dec_is
        ( Forward.Packed_forward { tag = "app"; entries_bytes = packed2 },
          [ (Msgpack.Str "compressed", Msgpack.Str "text") ] )
        (packed_frame (Msgpack.Bin packed2)
           [ Msgpack.Map [ (Msgpack.Str "compressed", Msgpack.Str "text") ] ])
    );
    ( "packed: compressed non-str rejects",
      dec_errs shape
        (packed_frame (Msgpack.Bin packed2)
           [ Msgpack.Map [ (Msgpack.Str "compressed", Msgpack.Int 1) ] ]) );
    ( "packed: compressed unknown value rejects",
      dec_errs shape
        (packed_frame (Msgpack.Bin packed2)
           [ Msgpack.Map [ (Msgpack.Str "compressed", Msgpack.Str "zstd") ] ])
    );
    ( "packed: truncated body names bad_msgpack",
      events_err
        (Err.Malformed Gate_core.Bad_msgpack)
        (packed_frame (Msgpack.Bin "\x92\x03") []) );
    ( "packed: empty body is zero events",
      events_are [] (packed_frame (Msgpack.Bin "") []) );
    ( "packed: reserved lead inside body names bad_msgpack",
      events_err
        (Err.Malformed Gate_core.Bad_msgpack)
        (packed_frame (Msgpack.Bin "\xc1") []) );
    ( "packed: entries_max entries accepted",
      Result.fold
        ~ok:(fun (evs : Forward.event list) -> List.length evs = 8192)
        ~error:(fun (_ : Err.t) -> false)
        (events_of (packed_frame (Msgpack.Bin (packed_n 8192)) [])) );
    ( "packed: entries_max + 1 rejects oversized",
      events_err
        (Err.Oversized Gate_core.Record_over)
        (packed_frame (Msgpack.Bin (packed_n 8193)) []) );
    (* Review r1/r2: packed entries must hit the same record rules as
       Message/Forward, and duplicate keys must reject at every level.
       A canonical-size mirror is unreachable in a packed body: it
       rides a Bin capped at string_max (256 KB), far under
       record_max, so the size dimension mirrors as the map pair-count
       cap instead. *)
    ( "packed: invalid utf-8 in an entry names bad_byte",
      events_err
        (Err.Bad_utf8 Gate_core.Bad_byte)
        (packed_frame
           (Msgpack.Bin
              (enc
                 (Msgpack.Arr
                    [ Msgpack.Int 0;
                      Msgpack.Map [ (Msgpack.Str "k", Msgpack.Str "\xff") ]
                    ])))
           []) );
    ( "packed: deep entry value names depth_over",
      events_err
        (Err.Oversized Gate_core.Depth_over)
        (packed_frame
           (Msgpack.Bin
              (enc
                 (Msgpack.Arr
                    [ Msgpack.Int 0;
                      Msgpack.Map [ (Msgpack.Str "k", deep_value) ] ])))
           []) );
    ( "packed: entry map over entries_max pairs names record_over",
      events_err
        (Err.Oversized Gate_core.Record_over)
        (packed_frame
           (Msgpack.Bin (enc (Msgpack.Arr [ Msgpack.Int 0; wide_map ])))
           []) );
    ( "packed: duplicate keys in an entry name duplicate_key",
      events_err
        (Err.Malformed Gate_core.Duplicate_key)
        (packed_frame
           (Msgpack.Bin
              (enc
                 (Msgpack.Arr
                    [ Msgpack.Int 0;
                      Msgpack.Map
                        [ (Msgpack.Str "a", Msgpack.Int 1);
                          (Msgpack.Str "a", Msgpack.Int 2) ] ])))
           []) );
    ( "map: nested duplicate keys name duplicate_key",
      dec_errs
        (Err.Malformed Gate_core.Duplicate_key)
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Int 0;
                Msgpack.Map
                  [ ( Msgpack.Str "k",
                      Msgpack.Map
                        [ (Msgpack.Str "a", Msgpack.Int 1);
                          (Msgpack.Str "a", Msgpack.Int 2) ] ) ] ])) );
    ( "options: duplicate compressed keys name duplicate_key",
      dec_errs
        (Err.Malformed Gate_core.Duplicate_key)
        (packed_frame (Msgpack.Bin packed2)
           [ Msgpack.Map
               [ (Msgpack.Str "compressed", Msgpack.Str "text");
                 (Msgpack.Str "compressed", Msgpack.Str "gzip") ] ]) );
    ( "tag: cap length accepted",
      dec_is
        (Forward.Forward { tag = tag_cap; entries = [] }, [])
        (enc (Msgpack.Arr [ Msgpack.Str tag_cap; Msgpack.Arr [] ])) );
    ( "tag: over cap names tag_over",
      dec_errs
        (Err.Oversized Gate_core.Tag_over)
        (enc (Msgpack.Arr [ Msgpack.Str tag_over; Msgpack.Arr [] ])) );
    ( "tag: empty rejects",
      dec_errs shape (enc (Msgpack.Arr [ Msgpack.Str ""; Msgpack.Arr [] ])) );
    ( "tag: invalid utf-8 names bad_byte",
      dec_errs
        (Err.Bad_utf8 Gate_core.Bad_byte)
        (enc (Msgpack.Arr [ Msgpack.Str "\xff"; Msgpack.Arr [] ])) );
    ( "tag: non-str rejects",
      dec_errs shape (enc (Msgpack.Arr [ Msgpack.Int 1; Msgpack.Arr [] ])) );
    ( "record: non-str key rejects",
      dec_errs shape
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Int 0;
                Msgpack.Map [ (Msgpack.Int 1, Msgpack.Str "v") ] ])) );
    ( "record: invalid utf-8 value names bad_byte",
      dec_errs
        (Err.Bad_utf8 Gate_core.Bad_byte)
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Int 0;
                Msgpack.Map [ (Msgpack.Str "k", Msgpack.Str "\xff") ] ])) );
    ( "record: invalid utf-8 deep in the tree names bad_byte",
      dec_errs
        (Err.Bad_utf8 Gate_core.Bad_byte)
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Int 0;
                Msgpack.Map
                  [ ( Msgpack.Str "k",
                      Msgpack.Arr
                        [ Msgpack.Map [ (Msgpack.Str "\xff", Msgpack.Int 1) ] ]
                    ) ] ])) );
    ( "record: bin payload exempt from utf-8",
      dec_is
        ( Forward.Message
            { tag = "app";
              time = Forward.Seconds 0;
              record = [ ("k", Msgpack.Bin "\xff\xff") ] },
          [] )
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Int 0;
                Msgpack.Map [ (Msgpack.Str "k", Msgpack.Bin "\xff\xff") ] ])) );
    ( "record: ext payload exempt from utf-8",
      dec_is
        ( Forward.Message
            { tag = "app";
              time = Forward.Seconds 0;
              record = [ ("k", Msgpack.Ext (5, "\xff")) ] },
          [] )
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Int 0;
                Msgpack.Map [ (Msgpack.Str "k", Msgpack.Ext (5, "\xff")) ] ]))
    );
    ( "record: canonical size over record_max names record_over",
      dec_errs
        (Err.Oversized Gate_core.Record_over)
        (enc (Msgpack.Arr [ app; Msgpack.Int 0; big_record ])) );
    ( "record: str over string_max names record_over via msgpack",
      dec_errs
        (Err.Oversized Gate_core.Record_over)
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Int 0;
                Msgpack.Map
                  [ (Msgpack.Str "k", Msgpack.Str (String.make 300_000 'a')) ]
              ])) );
    ( "map: duplicate record keys name duplicate_key",
      dec_errs
        (Err.Malformed Gate_core.Duplicate_key)
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Int 0;
                Msgpack.Map
                  [ (Msgpack.Str "a", Msgpack.Int 1);
                    (Msgpack.Str "a", Msgpack.Int 2) ] ])) );
    ( "map: depth over cap names depth_over",
      dec_errs
        (Err.Oversized Gate_core.Depth_over)
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Int 0; Msgpack.Map [ (Msgpack.Str "k", deep_value) ]
              ])) );
    ( "map: trailing bytes name bad_msgpack",
      dec_errs
        (Err.Malformed Gate_core.Bad_msgpack)
        (enc (Msgpack.Arr [ app; Msgpack.Int 0; rec_v ]) ^ "\x00") );
    ( "map: reserved lead names bad_msgpack",
      dec_errs (Err.Malformed Gate_core.Bad_msgpack) "\xc1" );
    ( "map: truncated frame names bad_msgpack",
      dec_errs (Err.Malformed Gate_core.Bad_msgpack) "\x92" );
    ("top: str rejects", dec_errs shape (enc (Msgpack.Str "x")));
    ("top: map rejects", dec_errs shape (enc (Msgpack.Map [])));
    ("top: empty array rejects", dec_errs shape (enc (Msgpack.Arr [])));
    ("top: lone tag rejects", dec_errs shape (enc (Msgpack.Arr [ app ])));
    ( "top: time without record rejects",
      dec_errs shape (enc (Msgpack.Arr [ app; Msgpack.Int 0 ])) );
    ( "top: arity 5 rejects",
      dec_errs shape
        (enc
           (Msgpack.Arr
              [ app; Msgpack.Int 0; rec_v; Msgpack.Map []; Msgpack.Map [] ])) );
    ( "top: nil second rejects",
      dec_errs shape (enc (Msgpack.Arr [ app; Msgpack.Nil ])) );
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
  | 0 -> print_endline "test_forward: PASS"
  | _ ->
    print_endline "test_forward: FAIL";
    exit 1
