/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint-mitigation-10b-1",
      "SqlStringInjectionHint-mitigation-10b-2",
      "SqlStringInjectionHint-mitigation-10b-3",
      "SqlStringInjectionHint-mitigation-10b-4",
      "SqlStringInjectionHint-mitigation-10b-5"
    })
public class SqlInjectionLesson10b implements AssignmentEndpoint {

  @PostMapping("/SqlInjectionMitigations/attack10b")
  @ResponseBody
  public AttackResult completed(@RequestParam String editor) {
    try {
      if (editor.isEmpty()) {
        return failed(this).feedback("sql-injection.10b.no-code").build();
      }

      editor = editor.replaceAll("\\<.*?>", "");

      String regexSetsUpConnection = "(?=.*getConnection.*)";
      String regexUsesPreparedStatement = "(?=.*PreparedStatement.*)";
      String regexUsesPlaceholder = "(?=.*\\=\\?.*|.*\\=\\s\\?.*)";
      String regexUsesSetString = "(?=.*setString.*)";
      String regexUsesExecute = "(?=.*execute.*)";
      String regexUsesExecuteUpdate = "(?=.*executeUpdate.*)";

      String codeline = editor.replace("\n", "").replace("\r", "");

      boolean setsUpConnection = this.checkText(regexSetsUpConnection, codeline);
      boolean usesPreparedStatement = this.checkText(regexUsesPreparedStatement, codeline);
      boolean usesSetString = this.checkText(regexUsesSetString, codeline);
      boolean usesPlaceholder = this.checkText(regexUsesPlaceholder, codeline);
      boolean usesExecute = this.checkText(regexUsesExecute, codeline);
      boolean usesExecuteUpdate = this.checkText(regexUsesExecuteUpdate, codeline);

      boolean hasImportant =
          setsUpConnection
              && usesPreparedStatement
              && usesPlaceholder
              && usesSetString
              && (usesExecute || usesExecuteUpdate);
      List<Diagnostic> hasCompiled = this.compileFromString(editor);

      if (hasImportant && hasCompiled.isEmpty()) {
        return success(this).feedback("sql-injection.10b.success").build();
      } else if (!hasCompiled.isEmpty()) {
        String errors = "";
        for (Diagnostic d : hasCompiled) {
          errors += d.getMessage(null) + "<br>";
        }
        return failed(this).feedback("sql-injection.10b.compiler-errors").output(errors).build();
      } else {
        return failed(this).feedback("sql-injection.10b.failed").build();
      }
    } catch (Exception e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  private List<Diagnostic> compileFromString(String s) {
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    DiagnosticCollector diagnosticsCollector = new DiagnosticCollector();
    StandardJavaFileManager fileManager =
        compiler.getStandardFileManager(diagnosticsCollector, null, null);
    JavaFileObject javaObjectFromString = getJavaFileContentsAsString(s);
    Iterable fileObjects = Arrays.asList(javaObjectFromString);
    JavaCompiler.CompilationTask task =
        compiler.getTask(null, fileManager, diagnosticsCollector, null, null, fileObjects);
    Boolean result = task.call();
    return diagnosticsCollector.getDiagnostics();
  }

  private SimpleJavaFileObject getJavaFileContentsAsString(String s) {
    StringBuilder javaFileContents =
        new StringBuilder(
            "import java.sql.*; public class TestClass { static String DBUSER; static String DBPW;"
                + " static String DBURL; public static void main(String[] args) {"
                + s
                + "}}");
    JavaObjectFromString javaFileObject = null;
    try {
      javaFileObject = new JavaObjectFromString("TestClass.java", javaFileContents.toString());
    } catch (Exception exception) {
      exception.printStackTrace();
    }
    return javaFileObject;
  }

  class JavaObjectFromString extends SimpleJavaFileObject {
    private String contents;

    public JavaObjectFromString(String className, String contents) throws Exception {
      super(new URI(className), Kind.SOURCE);
      this.contents = contents;
    }

    public CharSequence getCharContent(boolean ignoreEncodingErrors) throws IOException {
      return contents;
    }
  }

  private boolean checkText(String regex, String text) {
    Pattern p = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    Matcher m = p.matcher(text);
    return m.find();
  }
}
