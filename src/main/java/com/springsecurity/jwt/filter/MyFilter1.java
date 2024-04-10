package com.springsecurity.jwt.filter;

//import javax.servlet.Filter;

import jakarta.servlet.*;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("Filter In");
//        PrintWriter out = response.getWriter();
        chain.doFilter(request, response);
    }
}
