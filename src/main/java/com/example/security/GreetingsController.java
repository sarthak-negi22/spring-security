package com.example.security;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

    @GetMapping("/hello")
    public String helloWorld() {
        return "Hello world!";
    }

    @PreAuthorize("hasRole('USER')")     // telling spring that only users with specific roles can access this endpoint
    @GetMapping("/user")
    public String userEndPoint() {
        return "Hello user!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "Hello admin!";
    }


}

// default behaviour of Spring security: redirects to /login after accessing any end point (like here "/hello")
// default password is generated at every run in the console, with default username as "user"
// "/logout" is accessible to unauthenticate yourself
// all the endpoints are by default authenticated
// default authentication on "/login" is in-built form based authentication.