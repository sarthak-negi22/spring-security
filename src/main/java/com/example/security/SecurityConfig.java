package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration      // tells spring that this class provides config to the application context
@EnableWebSecurity      // activates spring security. Can create custom security filter
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());        // authenticate every request

//        making the http request stateless (no cookies maintained)
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());     // using basic authentication with default settings
        return http.build();
    }
}

// instead of a form, the basic authentication opens an alert box, and we can't access "/logout" and "/login"
// to logout, we just have to close the session
// in basic authentication, session is being managed by cookies
// in form based authentication, paylod tab contains the login credentials entered by user to authenticate