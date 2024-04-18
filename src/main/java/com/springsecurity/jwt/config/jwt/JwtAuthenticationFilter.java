package com.springsecurity.jwt.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springsecurity.jwt.config.auth.PrincipalDetails;
import com.springsecurity.jwt.model.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;

// UsernamePasswordAuthenticationFilter: when /login with username, password by POST method is requested, it works
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // worked when /login is requested
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        System.out.println("JwtAuthenticationFilter");
        try {

            // ** x-www-form-urlencoded
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }

            // ** JSON
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            // creating Token
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // authenticate with the created token
            // loadByUsername() in PricipalDetailsService is executed.
            // authentication: login info is contained
            Authentication authentication
                    = authenticationManager.authenticate(authenticationToken);

            // if principalDetails.getUser().getUsername() is printed, it means the info can be brought -> login success
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            return authentication; // then stored in session
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;

    }
}
