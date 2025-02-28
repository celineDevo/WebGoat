/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.securepasswords;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Locale;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurePasswordsAssignment implements AssignmentEndpoint {

  @PostMapping("SecurePasswords/assignment")
  @ResponseBody
  public AttackResult completed(@RequestParam String password) {
    Zxcvbn zxcvbn = new Zxcvbn();
    StringBuilder output = new StringBuilder();
    DecimalFormat df = new DecimalFormat("0", DecimalFormatSymbols.getInstance(Locale.ENGLISH));
    df.setMaximumFractionDigits(340);
    Strength strength = zxcvbn.measure(password);

    output.append("<b>Your Password: *******</b></br>");
    output.append("<b>Length: </b>").append(password.length()).append("</br>");
    output.append("<b>Estimated guesses needed to crack your password: </b>").append(df.format(strength.getGuesses())).append("</br>");
    output.append("<div style=\"float: left;padding-right: 10px;\"><b>Score: </b>").append(strength.getScore()).append("/4 </div>");
    if (strength.getScore() <= 1) {
      output.append(
          "<div style=\"background-color:red;width: 200px;border-radius: 12px;float:"
              + " left;\">&nbsp;</div></br>");
    } else if (strength.getScore() <= 3) {
      output.append(
          "<div style=\"background-color:orange;width: 200px;border-radius: 12px;float:"
              + " left;\">&nbsp;</div></br>");
    } else {
      output.append(
          "<div style=\"background-color:green;width: 200px;border-radius: 12px;float:"
              + " left;\">&nbsp;</div></br>");
    }
    output.append("<b>Estimated cracking time: </b>").append(calculateTime(
                (long) strength.getCrackTimeSeconds().getOnlineNoThrottling10perSecond())).append("</br>");
    if (strength.getFeedback().getWarning().length() != 0) {
      
          output.append("<b>Warning: </b>").append(strength.getFeedback().getWarning()).append("</br>");
    }
    // possible feedback: https://github.com/dropbox/zxcvbn/blob/master/src/feedback.coffee
    // maybe ask user to try also weak passwords to see and understand feedback?
    if (!strength.getFeedback().getSuggestions().isEmpty()) {
      output.append("<b>Suggestions:</b></br><ul>");
      for (String sug : strength.getFeedback().getSuggestions())
        output.append("<li>").append(sug).append("</li>");
      output.append("</ul></br>");
    }
    output.append("<b>Score: </b>").append(strength.getScore()).append("/4 </br>");

    if (strength.getScore() >= 4) {
      return success(this).feedback("securepassword-success").output(output.toString()).build();
    } else {
      return failed(this).feedback("securepassword-failed").output(output.toString()).build();
    }
  }

  public static String calculateTime(long seconds) {
    int s = 1;
    int min = 60 * s;
    int hr = 60 * min;
    int d = 24 * hr;
    int yr = 365 * d;

    long years = seconds / d / 365;
    long days = (seconds % yr) / d;
    long hours = (seconds % d) / hr;
    long minutes = (seconds % hr) / min;
    long sec = seconds % min * s;

    return years
        + " years "
        + days
        + " days "
        + hours
        + " hours "
        + minutes
        + " minutes "
        + sec
        + " seconds";
  }
}
