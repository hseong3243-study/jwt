package com.example.jwt.auth.jwt;

import com.example.jwt.auth.MemberRole;
import com.example.jwt.auth.jwt.request.CreateTokenCommand;
import com.example.jwt.auth.jwt.response.CustomClaims;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JJwtProvider implements JwtProvider {

    private static final String MEMBER_ID = "memberId";
    private static final String ROLE = "role";

    private final String issuer;
    private final int expirySeconds;
    private final SecretKey secretKey;
    private final JwtParser jwtParser;

    public JJwtProvider(
        @Value("${jwt.issuer}") String issuer,
        @Value("${jwt.expiry-seconds}") int expirySeconds,
        @Value("${jwt.secret}") String secret) {
        this.issuer = issuer;
        this.expirySeconds = expirySeconds;
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.jwtParser = Jwts.parser()
            .verifyWith(secretKey)
            .build();
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
            .signWith(secretKey)
            .compact();
    }

    @Override
    public CustomClaims parseToken(String token) {
        try {
            Claims claims = jwtParser.parseSignedClaims(token).getPayload();
            Long memberId = claims.get(MEMBER_ID, Long.class);
            String memberRole = claims.get(ROLE, String.class);
            List<String> authorities = MemberRole.valueOf(memberRole).getAuthorities();
            return CustomClaims.of(memberId, authorities);
        } catch (ExpiredJwtException ex) {
            log.info("[EX] {}: 만료된 JWT입니다.", ex.getClass().getSimpleName());
        } catch (JwtException ex) {
            log.info("[EX] {}: 잘못된 JWT입니다.", ex.getClass().getSimpleName());
        }
        throw new IllegalArgumentException("유효하지 않은 JWT입니다.");
    }
}
