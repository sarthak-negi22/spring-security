package com.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration      // tells spring that this class provides config to the application context
@EnableWebSecurity      // activates spring security. Can create custom security filter
@EnableMethodSecurity       // activates method related authorization
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.requestMatchers("/h2-console/**").permitAll()     // allows unauthenticated access to h2 console
                     .anyRequest().authenticated());        // authenticate every request

//        making the http request stateless (no cookies maintained)
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());     // using basic authentication with default settings
        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));        // allows h2 console to be displayed in a frame from the same origin
        http.csrf(AbstractHttpConfigurer::disable);     //disabled CSRF protection for testing h2-database
        return http.build();
    }

    @Bean
//    creating in-memory authentication
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}password1")    // this prefix is added to tell spring, to store this password as plain text
                .roles("USER")
                .build();
        UserDetails admin = User.withUsername("admin")
                .password("{noop}admin123")    // this prefix is added to tell spring, to store this password as plain text
                .roles("ADMIN")
                .build();

        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);

        return userDetailsManager;      // making the data to be saved in
//        return new InMemoryUserDetailsManager(user1, admin);

    }
}

// instead of a form, the basic authentication opens an alert box, and we can't access "/logout" and "/login"
// to logout, we just have to close the session
// in basic authentication, session is being managed by cookies
// in form based authentication, paylod tab contains the login credentials entered by user to authenticate

//  in postman, under Request Headers named as "Authorization", the encoded value is "username:password" which we enter