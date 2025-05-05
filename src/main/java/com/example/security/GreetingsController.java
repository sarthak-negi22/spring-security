package com.example.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

    @GetMapping("/hello")
    public String helloWorld() {
        return "Hello world!";
    }
}

// default behaviour of Spring security: redirects to /login.