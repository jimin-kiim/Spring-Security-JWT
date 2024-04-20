package com.springsecurity.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.springsecurity.jwt.config.auth.PrincipalDetails;
import com.springsecurity.jwt.model.User;
import com.springsecurity.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

/*
    BasicAuthenticationFilter: inherent filter in SpringSecurity
    address that needs authorization and authentication is requested
    -> passes through BasicAuthenticationFilter
    if not, doesn't do.
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        super.doFilterInternal(request, response, chain);
        System.out.println("address that needs authorization and authentication is requested");

        String jwtHeader = request.getHeader("Authorization");
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        String jwtToken = jwtHeader.replace("Bearer ", "");
        String username =
                JWT.require(Algorithm.HMAC512("rwa")).build()
                        .verify(jwtToken)
                        .getClaim("username")
                        .asString();
        System.out.println("USERNAME: "+ username);

        if (username != null) { // authenticated
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // creating authentication object without longin process(authenticate())
            // by using the JWT token whose signature is found to be valid,
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            principalDetails,
                            null,
                            principalDetails.getAuthorities());

            // storing authentication object in Spring Security session
            SecurityContextHolder.getContext()
                    .setAuthentication(authentication);

            chain.doFilter(request, response);
        }

    }
}
