package com.springsecurity.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true) // activating @Secured annotation
public class SecurityConfig {

    @Bean // register the object to be returned to IoC
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable(); // red line occurs but can be ignored
        http.authorizeHttpRequests(authorize -> authorize

                // when the client requests with /user/** url, authentication is needed
                .requestMatchers("/user/**").authenticated()

                // when the client requests with /manager/** url, the ones whose roles are ADMIN or MANAGER can only access
                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")

                // when the client requests with /admin/** url, the ones whose roles are ADMIN can only access
                .requestMatchers("/admin/**").hasAnyRole("ADMIN")

                // for other requests, permit all
                .anyRequest().permitAll())

                // If clients attempt to access without proper authentication it moves them to the login page
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // when the url "/login" called, security catches it and login with its style
                // -> so we don't need codes in controller for /login
                .defaultSuccessUrl("/");

        return http.build();
    }
}