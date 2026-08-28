(* M11: chunk ack.  A frame's option map may carry "chunk": an opaque
   id the client keeps until the server acknowledges the frame
   (at-least-once delivery).  [chunk_of] parses exactly that key out
   of the raw options; every other key (size, compressed,
   fluent_signal, ...) has its own consumer and stays raw.
   [response] encodes the msgpack ack map {"ack": id} the server
   returns on the same connection.

   Rules: the id must be a non-empty valid-UTF-8 Str (fluent-bit
   sends 24 base64 chars; msgpack's string_max already bounds the
   length), and any other shape is a typed reject.  No options or no
   "chunk" key means no ack is due (Ok None).  Msgpack.decode already
   rejects duplicate map keys, but [chunk_of] takes a bare assoc
   list, so it re-checks: two "chunk" keys are Duplicate_key, never
   first-wins.

   Ordering is the session's job (M21), not this module's: the ack
   goes upstream only after the downstream write (DESIGN section 2,
   ack loss). *)

let chunk_key : Msgpack.t = Msgpack.Str "chunk"

let bad_shape : Err.t = Err.Malformed Gate_core.Bad_frame_shape

let id_of (v : Msgpack.t) : (string, Err.t) result =
  match v with
  | Msgpack.Str s ->
    (match () with
     | () when String.length s = 0 -> Error bad_shape
     | () ->
       Utf8.validate s
       |> Result.map_error (fun (u : Gate_core.utf8_error) -> Err.Bad_utf8 u)
       |> Result.map (fun () -> s))
  | Msgpack.Nil | Msgpack.Bool _ | Msgpack.Int _ | Msgpack.Uint64_edge _
  | Msgpack.Float _ | Msgpack.Bin _ | Msgpack.Arr _ | Msgpack.Map _
  | Msgpack.Ext (_, _) -> Error bad_shape

let chunk_of (opts : Forward.options) : (string option, Err.t) result =
  match
    List.filter (fun ((k : Msgpack.t), (_ : Msgpack.t)) -> k = chunk_key) opts
  with
  | [] -> Ok None
  | [ ((_ : Msgpack.t), v) ] -> Result.map (fun id -> Some id) (id_of v)
  | ((_ : Msgpack.t), (_ : Msgpack.t)) :: ((_ : Msgpack.t), (_ : Msgpack.t)) :: _
    -> Error (Err.Malformed Gate_core.Duplicate_key)

let response (id : string) : string =
  Msgpack.encode (Msgpack.Map [ (Msgpack.Str "ack", Msgpack.Str id) ])
