package com.example.securitydemo;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes simple API endpoints to demonstrate access restrictions
 */
@RestController
public class AppController {

    @GetMapping("/public")
    public String publicContent() {
        return "Public content";
    }

    @GetMapping("/protected")
    public String protectedContent(Principal user) {
        return String.format("Protected content for %s", user.getName());
    }

    @GetMapping("/admin")
    public String adminContent(Principal user) {
        return String.format("Admin only content for %s", user.getName());
    }
}
