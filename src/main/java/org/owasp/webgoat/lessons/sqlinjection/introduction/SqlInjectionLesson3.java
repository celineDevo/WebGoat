/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    try (Connection connection = dataSource.getConnection()) {
      try (Statement statement =
          connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        Statement checkStatement =
            connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
        PreparedStatement preparedStatement = connection.preparedStatement(query,TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
        preparedStatement.executeUpdate();
        //statement.executeUpdate(query);
        //ResultSet results =
        //    checkStatement.executeQuery("SELECT * FROM employees WHERE last_name='Barnett';");
        String query2 = "SELECT * FROM employees WHERE last_name='Barnett';";
        PreparedStatement preparedStatement2 = connection.preparedStatement(query2);
        ResultSet results = preparedStatement2.executeQuery();
        StringBuilder output = new StringBuilder();
        // user completes lesson if the department of Tobi Barnett now is 'Sales'
        results.first();
        if ("Sales".equals(results.getString("department"))) {
          output.append("<span class='feedback-positive'>").append(query).append("</span>");
          output.append(SqlInjectionLesson8.generateTable(results));
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output(output.toString()).build();
        }

      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}
