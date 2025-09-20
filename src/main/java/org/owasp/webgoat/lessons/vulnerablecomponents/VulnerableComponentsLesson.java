/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.thoughtworks.xstream.XStream;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

@PostMapping("/VulnerableComponents/attack1")
public @ResponseBody AttackResult completed(@RequestParam String payload) {
    // ΔΙΟΡΘΩΣΗ: Ασφαλής διαμόρφωση XStream
    XStream xstream = new XStream();
    
    // Απενεργοποίηση όλων των τύπων πρώτα (whitelist approach)
    XStream.setupDefaultSecurity(xstream);
    
    // Επιτρέπουμε μόνο συγκεκριμένους ασφαλείς τύπους
    xstream.allowTypes(new Class[] { 
        ContactImpl.class,
        String.class,
        // Προσθήκη άλλων ασφαλών τύπων αν χρειάζεται
    });
    
    // Επιτρέπουμε μόνο συγκεκριμένα packages
    xstream.allowTypesByWildcard(new String[] {
        "org.owasp.webgoat.lessons.vulnerablecomponents.*"
    });
    
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    
    Contact contact = null;
    try {
        if (!StringUtils.isEmpty(payload)) {
            // ΔΙΟΡΘΩΣΗ: Validation του payload πριν το deserialization
            if (payload.length() > 10000) { // Περιορισμός μεγέθους
                return failed(this)
                    .feedback("vulnerable-components.close")
                    .output("Payload too large")
                    .build();
            }
            
            // Έλεγχος για επικίνδυνα patterns
            if (payload.contains("ProcessBuilder") || 
                payload.contains("Runtime") ||
                payload.contains("exec") ||
                payload.contains("java.lang.Runtime")) {
                return failed(this)
                    .feedback("vulnerable-components.close")
                    .output("Potentially malicious payload detected")
                    .build();
            }
            
            payload = payload
                .replace("+", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("> ", ">")
                .replace(" <", "<");
        }
        
        // Deserialization με exception handling
        contact = (Contact) xstream.fromXML(payload);
        
    } catch (Exception ex) {
        return failed(this)
            .feedback("vulnerable-components.close")
            .output("Deserialization failed: " + ex.getMessage())
            .build();
    }
    
    try {
        if (null != contact) {
            contact.getFirstName();
        }
        if (!(contact instanceof ContactImpl)) {
            return success(this).feedback("vulnerable-components.success").build();
        }
    } catch (Exception e) {
        return success(this)
            .feedback("vulnerable-components.success")
            .output(e.getMessage())
            .build();
    }
    
    return failed(this)
        .feedback("vulnerable-components.fromXML")
        .feedbackArgs(contact)
        .build();
}
