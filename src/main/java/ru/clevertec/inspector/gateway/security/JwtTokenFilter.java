package ru.clevertec.inspector.gateway.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
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

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenFilter extends GenericFilterBean {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        ObjectMapper objectMapper = new ObjectMapper();
        String accessToken = ((HttpServletRequest) request).getHeader("X-Access");
        if (accessToken != null) {
            try {
                if (jwtTokenProvider.validate(accessToken)) {
                    SecurityContextHolder.getContext().setAuthentication(jwtTokenProvider.getAuthentication(accessToken));
                }
            } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
                ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED, e.getLocalizedMessage());
                ((HttpServletResponse) response).setHeader("Content-Type", "application/json");
                ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getOutputStream().write(objectMapper.writeValueAsString(errorResponse).getBytes());
                log.error("ERROR: {}", e.getLocalizedMessage());
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
