package ru.clevertec.inspector.gatewayregistry.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.Base64;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.validityTime}")
    private long validityTime;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }


    public boolean validate(String accessToken) throws JwtException, IllegalArgumentException{
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(accessToken);
            return true;
    }

    public Authentication getAuthentication(String accessToken) {
        String userId = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(accessToken).getBody().getSubject();
        return new UsernamePasswordAuthenticationToken(userId, null, null);
    }
}
