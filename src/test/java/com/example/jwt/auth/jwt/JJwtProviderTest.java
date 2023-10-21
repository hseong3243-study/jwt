package com.example.jwt.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.jwt.auth.MemberRole;
import com.example.jwt.auth.jwt.request.CreateTokenCommand;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class JJwtProviderTest {

    String issuer = "issuer";
    int expirySeconds = 1000;
    String secret = "}:ASV~lS,%!I:ba^GBR<Q@cJN~!,Y0=zx7Rqwum+remZ>ayhI3$4dX$jx~@9[1F";
    JJwtProvider jJwtProvider = new JJwtProvider(issuer, expirySeconds, secret);

    @Nested
    @DisplayName("createToken 메서드 실행 시")
    class CreateTokenTest {

        @Test
        @DisplayName("성공")
        void success() {
            //given
            CreateTokenCommand command = new CreateTokenCommand(1L, MemberRole.USER);

            //when
            String token = jJwtProvider.createToken(command);

            //then
            assertThat(token).isNotBlank();
        }
    }

    @Nested
    @DisplayName("validateToken 메서드 실행 시")
    class ValidateTokenTest {

        CreateTokenCommand command = new CreateTokenCommand(1L, MemberRole.USER);
        String accessToken = jJwtProvider.createToken(command);

        @Test
        @DisplayName("성공")
        void success() {
            //given
            //when
            //then
            assertThatCode(() -> jJwtProvider.validateToken(accessToken))
                .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("IllegalArgumentException: 잘못된 토큰")
        void IllegalArgumentExceptionWhenInvalidJwt() {
            //given
            String invalidSecret = secret + "invalid";
            JJwtProvider invalidJJwtProvider
                = new JJwtProvider(issuer, expirySeconds, invalidSecret);
            String invalidAccessToken = invalidJJwtProvider.createToken(command);

            //when
            //then
            assertThatThrownBy(() -> jJwtProvider.validateToken(invalidAccessToken))
                .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("IllegalArgumentException: 만료된 토큰")
        void IllegalArgumentExceptionWhenExpiredJwt() {
            //given
            int expirySeconds = -1;
            JJwtProvider expiredJJwtProvider = new JJwtProvider(issuer, expirySeconds, secret);
            String expiredAccessToken = expiredJJwtProvider.createToken(command);

            //when
            //then
            assertThatThrownBy(() -> jJwtProvider.validateToken(expiredAccessToken))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }
}