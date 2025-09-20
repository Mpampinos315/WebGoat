/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.util.Base64;
import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "insecure-deserialization.hints.1",
  "insecure-deserialization.hints.2",
  "insecure-deserialization.hints.3"
})
public class InsecureDeserializationTask implements AssignmentEndpoint {

  @PostMapping("/InsecureDeserialization/task")
  @ResponseBody
 @PostMapping("/InsecureDeserialization/task")
@ResponseBody
public AttackResult completed(@RequestParam String token) throws IOException {
    String b64token;
    long before;
    long after;
    int delay;
    
    // Input validation
    if (token == null || token.trim().isEmpty()) {
        return failed(this).feedback("insecure-deserialization.invalidtoken").build();
    }
    
    // Size limit για το token
    if (token.length() > 10000) {
        return failed(this).feedback("insecure-deserialization.tokentoobig").build();
    }
    
    b64token = token.replace('-', '+').replace('_', '/');
    
    // ΔΙΟΡΘΩΣΗ: Χρήση ασφαλούς ObjectInputStream με filtering
    try {
        // Δημιουργία custom ObjectInputStream με whitelist
        ByteArrayInputStream bis = new ByteArrayInputStream(Base64.getDecoder().decode(b64token));
        SafeObjectInputStream ois = new SafeObjectInputStream(bis);
        
        before = System.currentTimeMillis();
        Object o = ois.readObject();
        
        if (!(o instanceof VulnerableTaskHolder)) {
            if (o instanceof String) {
                return failed(this).feedback("insecure-deserialization.stringobject").build();
            }
            return failed(this).feedback("insecure-deserialization.wrongobject").build();
        }
        after = System.currentTimeMillis();
        
    } catch (InvalidClassException e) {
        return failed(this).feedback("insecure-deserialization.invalidversion").build();
    } catch (IllegalArgumentException e) {
        return failed(this).feedback("insecure-deserialization.expired").build();
    } catch (SecurityException e) {
        return failed(this).feedback("insecure-deserialization.securityviolation").build();
    } catch (Exception e) {
        return failed(this).feedback("insecure-deserialization.invalidversion").build();
    }
    
    delay = (int) (after - before);
    if (delay > 7000) {
        return failed(this).build();
    }
    if (delay < 3000) {
        return failed(this).build();
    }
    return success(this).build();
}

// ΔΙΟΡΘΩΣΗ: Ασφαλής ObjectInputStream κλάση
private static class SafeObjectInputStream extends ObjectInputStream {
    
    private static final String[] ALLOWED_CLASSES = {
        "org.dummy.insecure.framework.VulnerableTaskHolder",
        "java.lang.String",
        "java.lang.Integer",
        "java.lang.Long",
        "java.util.Date"
    };
    
    public SafeObjectInputStream(java.io.InputStream in) throws IOException {
        super(in);
    }
    
    @Override
    protected Class<?> resolveClass(java.io.ObjectStreamClass desc) 
            throws IOException, ClassNotFoundException {
        
        String className = desc.getName();
        
        // Whitelist approach - επιτρέπουμε μόνο συγκεκριμένες κλάσεις
        boolean allowed = false;
        for (String allowedClass : ALLOWED_CLASSES) {
            if (className.equals(allowedClass)) {
                allowed = true;
                break;
            }
        }
        
        if (!allowed) {
            throw new SecurityException("Deserialization of class " + className + " is not allowed");
        }
        
        return super.resolveClass(desc);
    }
}
