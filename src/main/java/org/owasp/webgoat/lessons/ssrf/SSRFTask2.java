/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String url) {
    try {
        URL parsedUrl = new URL(url);

        // Allow only http(s) protocol and exact host match
        String host = parsedUrl.getHost();
        String protocol = parsedUrl.getProtocol();
        int port = parsedUrl.getPort();
        // Only allow http or https, no custom ports, and exact host match (case-insensitive)
        if (
            (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) ||
            !"ifconfig.pro".equalsIgnoreCase(host) ||
            (port != -1 && !((port == 80 && "http".equalsIgnoreCase(protocol)) || (port == 443 && "https".equalsIgnoreCase(protocol))))
        ) {
            return getFailedResult("Blocked URL: only http(s)://ifconfig.pro[:default_port] is allowed");
        }

        String html;
        try (InputStream in = parsedUrl.openStream()) {
            html = new String(in.readAllBytes(), StandardCharsets.UTF_8)
                     .replaceAll("\n", "<br>");
        } catch (IOException e) {
            html = "<html><body>Although the http://ifconfig.pro site is down, "
                 + "you still managed to solve this exercise the right way!</body></html>";
        }
        return success(this).feedback("ssrf.success").output(html).build();

    } catch (MalformedURLException e) {
        return getFailedResult("Invalid URL");
    } catch (Exception e) {
        return getFailedResult("Unexpected error: " + e.getMessage());
    }
}


  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
