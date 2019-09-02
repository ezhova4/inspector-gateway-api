package ru.clevertec.inspector.gatewayregistry.security;

import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtTokenFilter extends GenericFilterBean {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        String accessToken = ((HttpServletRequest)request).getHeader("X-Access");
        try {
            jwtTokenProvider.validate(accessToken);
        } catch (JwtException | IllegalArgumentException e) {
//            httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,"Invalid JWT token");
            throw new JwtException("Invalid JWT token", e);
        }
        SecurityContextHolder.getContext().setAuthentication(jwtTokenProvider.getAuthentication(accessToken));
        chain.doFilter(request, response);
    }
}
