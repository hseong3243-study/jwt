package com.example.jwt.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;

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
}