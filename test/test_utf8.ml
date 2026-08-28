(* M6 gate: the RFC 3629 corpus. Every boundary of the classification
   table in utf8.ml has a fixture on each side; one line per check, exit
   1 on any FAIL. *)

open Scrubline

let valid (s : string) : bool =
  Result.fold ~ok:(fun () -> true)
    ~error:(fun (_ : Gate_core.utf8_error) -> false)
    (Utf8.validate s)

let rejects (e : Gate_core.utf8_error) (s : string) : bool =
  Result.fold
    ~ok:(fun () -> false)
    ~error:(fun (got : Gate_core.utf8_error) -> got = e)
    (Utf8.validate s)

let checks : (string * bool) list =
  [
    (* accepted: one fixture per arm of the encoder table *)
    ("empty", valid "");
    ("ascii", valid "plain ascii, 127 max \x7f");
    ("two-byte floor U+0080", valid "\xc2\x80");
    ("two-byte ceiling U+07FF", valid "\xdf\xbf");
    ("three-byte floor U+0800", valid "\xe0\xa0\x80");
    ("e1..ec family", valid "\xe2\x82\xac");
    ("below surrogates U+D7FF", valid "\xed\x9f\xbf");
    ("above surrogates U+E000", valid "\xee\x80\x80");
    ("ee..ef ceiling U+FFFF", valid "\xef\xbf\xbf");
    ("four-byte floor U+10000", valid "\xf0\x90\x80\x80");
    ("f1..f3 family", valid "\xf1\x80\x80\x80");
    ("top of unicode U+10FFFF", valid "\xf4\x8f\xbf\xbf");
    ("mixed widths in one string", valid "a\xc3\xa9\xe2\x82\xac\xf0\x9f\x92\xa9z");
    (* Bad_byte *)
    ("bare continuation", rejects Gate_core.Bad_byte "\x80");
    ("bare continuation high", rejects Gate_core.Bad_byte "\xbf");
    ("fe is never a lead", rejects Gate_core.Bad_byte "\xfe");
    ("ff is never a lead", rejects Gate_core.Bad_byte "\xff");
    ("ascii in a continuation slot", rejects Gate_core.Bad_byte "\xc2\x41");
    ("lead in a continuation slot", rejects Gate_core.Bad_byte "\xc2\xc0");
    ("bad third byte", rejects Gate_core.Bad_byte "\xe1\x80\x41");
    ("bad fourth byte", rejects Gate_core.Bad_byte "\xf1\x80\x80\x41");
    ("defect after valid prefix", rejects Gate_core.Bad_byte "abc\x80");
    (* Overlong *)
    ("c0 lead", rejects Gate_core.Overlong "\xc0\xaf");
    ("c1 lead", rejects Gate_core.Overlong "\xc1\xbf");
    ("e0 second byte floor", rejects Gate_core.Overlong "\xe0\x80\xaf");
    ("e0 second byte ceiling", rejects Gate_core.Overlong "\xe0\x9f\xbf");
    ("f0 second byte floor", rejects Gate_core.Overlong "\xf0\x80\x80\x80");
    ("f0 second byte ceiling", rejects Gate_core.Overlong "\xf0\x8f\xbf\xbf");
    ("overlong proven at byte two", rejects Gate_core.Overlong "\xe0\x80");
    (* Surrogate *)
    ("surrogate floor U+D800", rejects Gate_core.Surrogate "\xed\xa0\x80");
    ("surrogate ceiling U+DFFF", rejects Gate_core.Surrogate "\xed\xbf\xbf");
    ("surrogate proven at byte two", rejects Gate_core.Surrogate "\xed\xa0");
    (* Out_of_range *)
    ("first scalar past the top", rejects Gate_core.Out_of_range "\xf4\x90\x80\x80");
    ("f5 lead", rejects Gate_core.Out_of_range "\xf5\x80\x80\x80");
    ("fd lead", rejects Gate_core.Out_of_range "\xfd");
    ("out of range proven at byte two", rejects Gate_core.Out_of_range "\xf4\x90");
    (* Truncated *)
    ("two-byte cut", rejects Gate_core.Truncated "\xc2");
    ("three-byte cut after two", rejects Gate_core.Truncated "\xe0\xa0");
    ("e1 cut after one", rejects Gate_core.Truncated "\xe1");
    ("four-byte cut after three", rejects Gate_core.Truncated "\xf0\x90\x80");
    ("f4 cut after three", rejects Gate_core.Truncated "\xf4\x8f\xbf");
    ("cut after valid prefix", rejects Gate_core.Truncated "abc\xc3");
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
  | 0 -> print_endline "test_utf8: PASS"
  | _ ->
    print_endline "test_utf8: FAIL";
    exit 1
