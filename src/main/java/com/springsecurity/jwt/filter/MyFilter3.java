package com.springsecurity.jwt.filter;

import jakarta.servlet.*;

import java.io.IOException;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("Filter3 In");
        chain.doFilter(request, response);
    }
}
