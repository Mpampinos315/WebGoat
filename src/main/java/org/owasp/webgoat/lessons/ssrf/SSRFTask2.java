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
        
        // ΔΙΟΡΘΩΣΗ SSRF: Πιο αυστηρός έλεγχος URL
        String host = parsedUrl.getHost();
        String protocol = parsedUrl.getProtocol();
        int port = parsedUrl.getPort();
        
        // Validate protocol
        if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
            return getFailedResult("Blocked URL: only http/https protocols allowed");
        }
        
        // Validate host - πιο αυστηρός έλεγχος
        if (host == null || !host.equalsIgnoreCase("ifconfig.pro")) {
            return getFailedResult("Blocked URL: only ifconfig.pro host is allowed");
        }
        
        // Validate port
        if (port != -1 && 
            !((port == 80 && "http".equalsIgnoreCase(protocol)) || 
              (port == 443 && "https".equalsIgnoreCase(protocol)))) {
            return getFailedResult("Blocked URL: only default ports allowed");
        }
        
        // ΔΙΟΡΘΩΣΗ: Χρήση HttpClient με timeout αντί για parsedUrl.openStream()
        String html;
        try {
            // Χρήση Java 11+ HttpClient για καλύτερο έλεγχο
            java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(5))
                .build();
                
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(parsedUrl.toURI())
                .timeout(java.time.Duration.ofSeconds(10))
                .GET()
                .build();
                
            java.net.http.HttpResponse<String> response = client.send(request, 
                java.net.http.HttpResponse.BodyHandlers.ofString());
                
            html = response.body().replaceAll("\n", "<br>");
            
        } catch (IOException | InterruptedException | java.net.URISyntaxException e) {
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
