// Oracle corpus for JavaScript authority TARGET RESOLUTION.
//
// Each writer below exercises one resolution case the JS adapter must handle:
//   literal      -- fs.writeFileSync("config.json", ...)        -> "config.json" / string_literal
//   var_const    -- const p = "out.json"; fs.writeFile(p, ...)  -> "out.json"    / string_literal
//   var_let      -- let q = "data.txt"; fs.writeFileSync(q, ...) -> "data.txt"    / string_literal
//   var_var      -- var r = "old.txt"; fs.writeFile(r, ...)      -> "old.txt"     / string_literal
//   join         -- const j = path.join("a","b.json"); fs.writeFile(j,..) -> "a/b.json" / path_constructor
//   inline_join  -- fs.writeFile(path.join("d","e.txt"), ...)   -> "d/e.txt"     / path_constructor
//   param        -- function f(target){ fs.writeFile(target,..)} -> __unknown_target__ / function_parameter
//   stream       -- fs.createWriteStream("stream.log")          -> "stream.log"  / string_literal
//   append       -- fs.appendFileSync("log.txt", ...)           -> "log.txt"     / string_literal (fs_append)
//   unresolvable -- repo.save(entity) (ORM, no path)            -> __unknown_target__ / unknown
//
// This file is parsed by the JavascriptAdapter only; it is not compiled or run.
const fs = require("fs");
const path = require("path");

// literal: bare string literal as the path argument.
function writeLiteral(data) {
  fs.writeFileSync("config.json", data);
}

// var_const: const bound to a literal.
function writeVarConst(data) {
  const p = "out.json";
  fs.writeFile(p, data, () => {});
}

// var_let: let bound to a literal.
function writeVarLet(data) {
  let q = "data.txt";
  fs.writeFileSync(q, data);
}

// var_var: var bound to a literal.
function writeVarVar(data) {
  var r = "old.txt";
  fs.writeFile(r, data, () => {});
}

// join: const bound to path.join of two literals.
function writeJoin(data) {
  const j = path.join("a", "b.json");
  fs.writeFile(j, data, () => {});
}

// inline_join: path.join passed DIRECTLY as the arg.
function writeInlineJoin(data) {
  fs.writeFile(path.join("d", "e.txt"), data, () => {});
}

// param: path comes from a function parameter (no literal in scope).
function writeParam(target, data) {
  fs.writeFile(target, data, () => {});
}

// stream: createWriteStream whose first arg is a string literal.
function writeStream() {
  const ws = fs.createWriteStream("stream.log");
}

// append: appendFileSync -> fs_append write_kind, literal target.
function appendLiteral(data) {
  fs.appendFileSync("log.txt", data);
}

// unresolvable: ORM save -- receiver is not a path target.
function saveEntity(repo, entity) {
  repo.save(entity);
}

module.exports = {
  writeLiteral, writeVarConst, writeVarLet, writeVarVar,
  writeJoin, writeInlineJoin, writeParam, writeStream,
  appendLiteral, saveEntity,
};
