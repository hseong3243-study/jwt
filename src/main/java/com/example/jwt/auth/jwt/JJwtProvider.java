package com.example.jwt.auth.jwt;

import com.example.jwt.auth.jwt.response.MemberToken;
import com.example.jwt.member.MemberRole;
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

    private static final String ROLE = "role";

    private final String issuer;
    private final int expirySeconds;
    private final int refreshExpirySeconds;
    private final SecretKey secretKey;
    private final SecretKey refreshSecretKey;
    private final JwtParser accessTokenParser;
    private final JwtParser refreshTokenParser;


    public JJwtProvider(
        @Value("${jwt.issuer}") String issuer,
        @Value("${jwt.expiry-seconds}") int expirySeconds,
        @Value("${jwt.refresh-expiry-seconds}") int refreshExpirySeconds,
        @Value("${jwt.secret}") String secret,
        @Value("${jwt.refresh-secret}") String refreshSecret) {
        this.issuer = issuer;
        this.expirySeconds = expirySeconds;
        this.refreshExpirySeconds = refreshExpirySeconds;
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.refreshSecretKey = Keys.hmacShaKeyFor(refreshSecret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenParser = Jwts.parser()
            .verifyWith(secretKey)
            .build();
        this.refreshTokenParser = Jwts.parser()
            .verifyWith(refreshSecretKey)
            .build();
    }

    @Override
    public MemberToken createToken(CreateTokenCommand command) {
        Long memberId = command.memberId();
        MemberRole memberRole = command.memberRole();
        String accessToken = createAccessToken(memberId, memberRole);
        String refreshToken = createRefreshToken(memberId, memberRole);
        return MemberToken.of(accessToken, refreshToken);
    }

    private String createAccessToken(Long memberId, MemberRole memberRole) {
        Date now = new Date();
        Date expiresAt = new Date(now.getTime() + expirySeconds * 1000L);
        return Jwts.builder()
            .issuer(issuer)
            .issuedAt(now)
            .subject(memberId.toString())
            .expiration(expiresAt)
            .claim(ROLE, memberRole.getValue())
            .signWith(secretKey)
            .compact();
    }

    private String createRefreshToken(Long memberId, MemberRole memberRole) {
        Date now = new Date();
        Date expiresAt = new Date(now.getTime() + refreshExpirySeconds * 1000L);
        return Jwts.builder()
            .issuer(issuer)
            .issuedAt(now)
            .subject(memberId.toString())
            .expiration(expiresAt)
            .claim(ROLE, memberRole.getValue())
            .signWith(refreshSecretKey)
            .compact();
    }

    @Override
    public CustomClaims parseAccessToken(String token) {
        try {
            Claims claims = accessTokenParser.parseSignedClaims(token).getPayload();
            Long memberId = Long.valueOf(claims.getSubject());
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

    @Override
    public MemberToken refreshAccessToken(String refreshToken) {
        try {
            Claims claims = refreshTokenParser.parseSignedClaims(refreshToken).getPayload();
            Long memberId = Long.valueOf(claims.getSubject());
            MemberRole memberRole = MemberRole.valueOf(claims.get(ROLE, String.class));
            CreateTokenCommand command = CreateTokenCommand.of(memberId, memberRole);
            return createToken(command);
        } catch (ExpiredJwtException ex) {
            log.info("[EX] {}: 만료된 리프레시 토큰입니다.", ex.getClass().getSimpleName());
        } catch (JwtException ex) {
            log.info("[EX] {}: 잘못된 리프레시 토큰입니다.", ex.getClass().getSimpleName());
        }
        throw new IllegalArgumentException("유효하지 않은 리프레시 토큰입니다.");
    }
}
