/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

public class ProgressRaceConditionIntegrationTest extends IntegrationTest {

  @Test
  public void runTests() throws InterruptedException {
    int numberOfCalls = 40;
    int numberOfParallelThreads = 5;
    startLesson("Challenge1");

    Callable<Response> call =
        () ->
          // System.out.println("thread "+Thread.currentThread().getName());
          RestAssured.given()
              .when()
              .relaxedHTTPSValidation()
              .cookie("JSESSIONID", getWebGoatCookie())
              .formParams(Map.of("flag", "test"))
              .post(url("challenge/flag/1"));
    ExecutorService executorService = Executors.newFixedThreadPool(numberOfParallelThreads);
    List<? extends Callable<Response>> flagCalls =
        IntStream.range(0, numberOfCalls).mapToObj(i -> call).collect(Collectors.toList());
    var responses = executorService.invokeAll(flagCalls);

    // A certain amount of parallel calls should fail as optimistic locking in DB is applied
    long countStatusCode500 =
        responses.stream()
            .filter(
                r -> {
                  try {
                    // System.err.println(r.get().getStatusCode());
                    return r.get().getStatusCode() != 200;
                  } catch (InterruptedException | ExecutionException e) {
                    // System.err.println(e);
                    throw new IllegalStateException(e);
                  }
                })
            .count();
    System.err.println("counted status 500: " + countStatusCode500);
    Assertions.assertThat(countStatusCode500)
        .isLessThanOrEqualTo((numberOfCalls - (numberOfCalls / numberOfParallelThreads)));
  }
}
