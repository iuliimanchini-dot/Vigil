// Oracle corpus for Swift authority TARGET RESOLUTION.
//
// Each writer below exercises one resolution case the Swift adapter must handle:
//   atpath_lit   -- FileManager.default.createFile(atPath: "created.txt", ...) -> "created.txt" / string_literal
//   url_ctor     -- data.write(to: URL(fileURLWithPath: "config.json"))        -> "config.json" / path_constructor
//   var_str      -- let p = "out.json"; FileManager...createFile(atPath: p)    -> "out.json"    / string_literal
//   var_url      -- let u = URL(fileURLWithPath: "data.bin"); data.write(to: u)-> "data.bin"    / path_constructor
//   param        -- func f(target: String){ ...createFile(atPath: target) }    -> __unknown_target__ / function_parameter
//   param_url    -- func g(target: String){ data.write(to: URL(fileURLWithPath: target)) } -> __unknown_target__ / function_parameter
//   save         -- context.save() (Core Data, no path)                        -> __unknown_target__ / unknown
//   handle_write -- handle.write(buffer) (stream/handle, no to: label)         -> __unknown_target__ / unknown
//
// This file is parsed by the SwiftAdapter only; it is not compiled or run.
import Foundation

// atpath_lit: bare string literal in the atPath: argument.
func writeAtPathLiteral() {
    FileManager.default.createFile(atPath: "created.txt", contents: nil)
}

// url_ctor: write(to:) wrapping a literal in URL(fileURLWithPath:).
func writeURLCtor(data: Data) {
    try? data.write(to: URL(fileURLWithPath: "config.json"))
}

// var_str: let bound to a literal, used as the atPath: argument.
func writeVarString() {
    let p = "out.json"
    FileManager.default.createFile(atPath: p, contents: nil)
}

// var_url: let bound to a URL path-constructor, used as the to: argument.
func writeVarURL(data: Data) {
    let u = URL(fileURLWithPath: "data.bin")
    try? data.write(to: u)
}

// param: atPath: comes from a function parameter (no literal in scope).
func writeParam(target: String) {
    FileManager.default.createFile(atPath: target, contents: nil)
}

// param_url: parameter wrapped in URL(fileURLWithPath: target).
func writeParamURL(target: String, data: Data) {
    try? data.write(to: URL(fileURLWithPath: target))
}

// save: Core Data save -- receiver is not a path target.
func saveContext(context: NSManagedObjectContext) {
    try? context.save()
}

// handle_write: stream/handle write with no to: label -> unresolvable.
func handleWrite(handle: FileHandle, buffer: Data) {
    handle.write(buffer)
}
