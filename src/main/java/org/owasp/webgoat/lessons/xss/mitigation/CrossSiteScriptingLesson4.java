/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(value = {"xss-mitigation-4-hint1"})
public class CrossSiteScriptingLesson4 implements AssignmentEndpoint {

  @PostMapping("/CrossSiteScripting/attack4")
  @ResponseBody
  public AttackResult completed(@RequestParam String editor2) {

    String editor = editor2.replaceAll("\\<.*?>", "");

    try {
      Policy policy = Policy.getInstance("antisamy-slashdot.xml");
      AntiSamy as = new AntiSamy();
      CleanResults cr = as.scan(editor2, policy);
      String cleanHTML = cr.getCleanHTML();

      return success(this).feedback("xss-mitigation-4-success").build();
    } else {
      return failed(this).feedback("xss-mitigation-4-failed").build();
    }
  }
}
