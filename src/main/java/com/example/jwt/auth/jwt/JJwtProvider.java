package com.example.jwt.auth.jwt;

import com.example.jwt.auth.jwt.request.CreateTokenCommand;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JJwtProvider implements JwtProvider {

    private static final String MEMBER_ID = "memberId";
    private static final String ROLE = "role";

    private final String issuer;
    private final int expirySeconds;
    private final String secret;

    public JJwtProvider(
        @Value("${jwt.issuer}") String issuer,
        @Value("${jwt.expiry-seconds}") int expirySeconds,
        @Value("${jwt.secret}") String secret) {
        this.issuer = issuer;
        this.expirySeconds = expirySeconds;
        this.secret = secret;
    }

    @Override
    public String createToken(CreateTokenCommand command) {
        Date now = new Date();
        Date expiresAt = new Date(now.getTime() + expirySeconds * 1000L);
        return Jwts.builder()
            .issuer(issuer)
            .issuedAt(now)
            .expiration(expiresAt)
            .claim(MEMBER_ID, command.memberId())
            .claim(ROLE, command.memberRole().getValue())
            .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
            .compact();
    }
}
