// Oracle corpus for Go authority TARGET RESOLUTION.
//
// Each writer below exercises one resolution case the Go adapter must handle:
//   literal      -- os.WriteFile("config.json", ...)        -> "config.json" / string_literal
//   var_short    -- p := "out.json"; os.WriteFile(p, ...)   -> "out.json"    / string_literal
//   var_decl     -- var q = "data.txt"; os.WriteFile(q, ...)-> "data.txt"    / string_literal
//   join         -- j := filepath.Join("a","b"); WriteFile(j,..) -> "a/b"    / path_constructor
//   param        -- func(target string){ WriteFile(target,..)}  -> ""        / function_parameter
//   unresolvable -- w.Write(...) (receiver, no path)         -> __unknown_target__ / unknown
//
// This file is parsed by the GoAdapter only; it is not compiled or run.
package oracletarget

import (
	"os"
	"path/filepath"
)

// WriteLiteral: first arg is a bare string literal.
func WriteLiteral() {
	os.WriteFile("config.json", []byte("x"), 0644)
}

// WriteVarShort: first arg is a short-var-declared name bound to a literal.
func WriteVarShort() {
	p := "out.json"
	os.WriteFile(p, []byte("x"), 0644)
}

// WriteVarDecl: first arg is a `var` declared name bound to a literal.
func WriteVarDecl() {
	var q = "data.txt"
	os.WriteFile(q, []byte("x"), 0644)
}

// WriteJoin: first arg is a name bound to filepath.Join of two literals.
func WriteJoin() {
	j := filepath.Join("a", "b")
	os.WriteFile(j, []byte("x"), 0644)
}

// WriteParam: first arg is a function parameter (no literal value in scope).
func WriteParam(target string) {
	os.WriteFile(target, []byte("x"), 0644)
}

// WriteReceiver: receiver-method write with no resolvable path target.
func WriteReceiver(w writer) {
	w.Write([]byte("x"))
}

type writer interface {
	Write(p []byte) (int, error)
}
