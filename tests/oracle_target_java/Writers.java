// Oracle corpus for Java authority TARGET RESOLUTION.
//
// Each writer below exercises one resolution case the Java adapter must handle:
//   literal      -- Files.writeString("config.json", ...)          -> "config.json" / string_literal
//   path_of_lit  -- Files.write(Path.of("plain.txt"), ...)         -> "plain.txt"   / string_literal
//   var_local    -- String q = "data.txt"; Files.writeString(q,..) -> "data.txt"    / string_literal
//   join         -- Files.write(Paths.get("a","b.json"), ...)      -> "a/b.json"    / path_constructor
//   var_join     -- Path j = Path.of("d","e.txt"); Files.write(j,..)-> "d/e.txt"    / path_constructor
//   param        -- void f(String target){ Files.write(Path.of(target),..)} -> __unknown_target__ / function_parameter
//   filewriter   -- new FileWriter("direct.log")                   -> "direct.log"  / string_literal
//   unresolvable -- writer.write(...) (receiver, no path)          -> __unknown_target__ / unknown
//   orm_save     -- repo.save(entity) (receiver, no path)          -> __unknown_target__ / unknown
//
// This file is parsed by the JavaAdapter only; it is not compiled or run.
package oracletarget;

import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Writers {

    // literal: bare string literal as the path argument.
    void writeLiteral() throws Exception {
        Files.writeString("config.json", "x");
    }

    // path_of_lit: single-literal Path.of wrapper -> the literal itself.
    void writePathOfLiteral() throws Exception {
        Files.write(Path.of("plain.txt"), new byte[0]);
    }

    // var_local: local String bound to a literal, then used as the arg.
    void writeVarLocal() throws Exception {
        String q = "data.txt";
        Files.writeString(q, "x");
    }

    // join: inline Paths.get of two literals -> joined path.
    void writeJoin() throws Exception {
        Files.write(Paths.get("a", "b.json"), new byte[0]);
    }

    // var_join: local Path bound to Path.of of two literals.
    void writeVarJoin() throws Exception {
        Path j = Path.of("d", "e.txt");
        Files.write(j, new byte[0]);
    }

    // param: path comes from a method parameter (no literal in scope).
    void writeParam(String target) throws Exception {
        Files.write(Path.of(target), new byte[0]);
    }

    // filewriter: constructor whose first arg is a string literal.
    void writeFileWriter() throws Exception {
        FileWriter fw = new FileWriter("direct.log");
    }

    // unresolvable: receiver-method write with no resolvable path target.
    void writeReceiver(java.io.Writer writer) throws Exception {
        writer.write("x");
    }

    // orm_save: repository save -- receiver is not a path target.
    void saveEntity(Object entity) {
        repo.save(entity);
    }

    Object repo;
}
