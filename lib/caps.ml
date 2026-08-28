(* M5: every size cap in one module, checked before allocation (DESIGN
   section 3). A cap lives here or it does not exist: decoders take these
   constants, never a literal, so the strictness profile is one diff. *)

let frame_max : int = 4 * 1024 * 1024

let record_max : int = 1024 * 1024

let tag_max : int = 1024

let depth_max : int = 32

let entries_max : int = 8192

let string_max : int = 256 * 1024
