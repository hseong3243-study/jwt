package com.example.jwt.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.jwt.auth.jwt.request.CreateTokenCommand;
import com.example.jwt.auth.jwt.response.CustomClaims;
import com.example.jwt.member.MemberRole;
import com.example.jwt.support.AuthFixture;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class JJwtProviderTest {

    String issuer = "issuer";
    int expirySeconds = 1000;
    int refreshExpirySeconds = 10000;
    String secret = "}:ASV~lS,%!I:ba^GBR<Q@cJN~!,Y0=zx7Rqwum+remZ>ayhI3$4dX$jx~@9[1F";
    String refreshSecret = "~GWW.|?:\"#Rqmm^-nk#>#4Ngc}]3xz!hOQCXNF:8z-Mdn\"U!Vt</+/8;ATR*lc{";
    JJwtProvider jJwtProvider = AuthFixture.jJwtProvider();

    @Nested
    @DisplayName("createToken 메서드 실행 시")
    class CreateTokenTest {

        @Test
        @DisplayName("성공")
        void success() {
            //given
            CreateTokenCommand command = new CreateTokenCommand(1L, MemberRole.ROLE_USER);

            //when
            MemberToken memberToken = jJwtProvider.createToken(command);

            //then
            assertThat(memberToken.accessToken()).isNotBlank();
            assertThat(memberToken.refreshToken()).isNotBlank();
            assertThat(memberToken.accessToken()).isNotEqualTo(memberToken.refreshToken());
        }
    }

    @Nested
    @DisplayName("validateToken 메서드 실행 시")
    class ValidateTokenTest {

        CreateTokenCommand command = new CreateTokenCommand(1L, MemberRole.ROLE_USER);
        MemberToken memberToken = jJwtProvider.createToken(command);

        @Test
        @DisplayName("성공")
        void success() {
            //given
            //when
            CustomClaims claims = jJwtProvider.parseToken(memberToken.accessToken());

            //then
            Long memberId = claims.memberId();
            List<String> authorities = claims.authorities();
            assertThat(memberId).isEqualTo(command.memberId());
            assertThat(authorities).containsExactlyElementsOf(
                command.memberRole().getAuthorities());
        }

        @Test
        @DisplayName("IllegalArgumentException: 잘못된 토큰")
        void IllegalArgumentExceptionWhenInvalidJwt() {
            //given
            String invalidSecret = secret + "invalid";
            JJwtProvider invalidJJwtProvider = new JJwtProvider(issuer, expirySeconds,
                refreshExpirySeconds, invalidSecret, refreshSecret);
            MemberToken memberToken = invalidJJwtProvider.createToken(command);
            String invalidAccessToken = memberToken.accessToken();

            //when
            //then
            assertThatThrownBy(
                () -> jJwtProvider.parseToken(invalidAccessToken))
                .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("IllegalArgumentException: 만료된 토큰")
        void IllegalArgumentExceptionWhenExpiredJwt() {
            //given
            int expirySeconds = -1;
            JJwtProvider expiredJJwtProvider = new JJwtProvider(issuer, expirySeconds,
                refreshExpirySeconds, secret, refreshSecret);
            MemberToken memberToken = expiredJJwtProvider.createToken(command);
            String expiredAccessToken = memberToken.accessToken();

            //when
            //then
            assertThatThrownBy(() -> jJwtProvider.parseToken(expiredAccessToken))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
