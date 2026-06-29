// Oracle corpus for TypeScript authority TARGET RESOLUTION.
//
// Each writer below exercises one resolution case the TS adapter must handle:
//   literal      -- fs.writeFileSync("config.json", ...)        -> "config.json" / string_literal
//   var_const    -- const p = "out.json"; fs.writeFile(p, ...)  -> "out.json"    / string_literal
//   var_let      -- let q = "data.txt"; fs.writeFileSync(q, ...) -> "data.txt"    / string_literal
//   join         -- const j = path.join("a","b.json"); fs.writeFile(j,..) -> "a/b.json" / path_constructor
//   inline_join  -- fs.writeFile(path.join("d","e.txt"), ...)   -> "d/e.txt"     / path_constructor
//   param        -- function f(target: string){ fs.writeFile(target,..)} -> __unknown_target__ / function_parameter
//   stream       -- fs.createWriteStream("stream.log")          -> "stream.log"  / string_literal
//   append       -- fs.appendFileSync("log.txt", ...)           -> "log.txt"     / string_literal (fs_append)
//   unresolvable -- repo.save(entity) (ORM, no path)            -> __unknown_target__ / unknown
//
// This file is parsed by the TypescriptAdapter only; it is not compiled or run.
import * as fs from "fs";
import * as path from "path";

// literal: bare string literal as the path argument.
export function writeLiteral(data: string): void {
  fs.writeFileSync("config.json", data);
}

// var_const: const bound to a literal, then used as the arg.
export function writeVarConst(data: string): void {
  const p = "out.json";
  fs.writeFile(p, data, () => {});
}

// var_let: let bound to a literal, then used as the arg.
export function writeVarLet(data: string): void {
  let q = "data.txt";
  fs.writeFileSync(q, data);
}

// join: const bound to path.join of two literals.
export function writeJoin(data: string): void {
  const j = path.join("a", "b.json");
  fs.writeFile(j, data, () => {});
}

// inline_join: path.join passed DIRECTLY as the arg (no intermediate var).
export function writeInlineJoin(data: string): void {
  fs.writeFile(path.join("d", "e.txt"), data, () => {});
}

// param: path comes from a function parameter (no literal in scope).
export function writeParam(target: string, data: string): void {
  fs.writeFile(target, data, () => {});
}

// stream: createWriteStream whose first arg is a string literal.
export function writeStream(): void {
  const ws = fs.createWriteStream("stream.log");
}

// append: appendFileSync -> fs_append write_kind, literal target.
export function appendLiteral(data: string): void {
  fs.appendFileSync("log.txt", data);
}

// unresolvable: ORM save -- receiver is not a path target.
export function saveEntity(repo: any, entity: any): void {
  repo.save(entity);
}
