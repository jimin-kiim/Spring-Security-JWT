package com.springsecurity.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
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
import java.util.Date;

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
            System.out.println(user);

            // creating Token
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            System.out.println("TOKEN created");

            // authenticate with the created token
            // loadByUsername() in PricipalDetailsService is executed.
            // authentication: login info is contained
            Authentication authentication
                    = authenticationManager.authenticate(authenticationToken);
            System.out.println("Authentication"+ authentication); // login succeeded

            // if principalDetails.getUser().getUsername() is printed, it means the info can be brought -> login success
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("Username:"+ principalDetails.getUser().getUsername());
            System.out.println("Authentication : "+ principalDetails.getUser().getUsername());
            return authentication; // then stored in session
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // after the authentication through attemptAuthentication is successfully performed
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult)
            throws IOException, ServletException {
        System.out.println("successfulAuthentication");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA (X) Hash encryption method
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
    }
}
