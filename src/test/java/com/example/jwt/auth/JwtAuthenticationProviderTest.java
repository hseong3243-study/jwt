package com.example.jwt.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.jwt.auth.authentication.JwtAuthentication;
import com.example.jwt.auth.authentication.JwtAuthenticationProvider;
import com.example.jwt.auth.jwt.JwtProvider;
import com.example.jwt.auth.jwt.response.MemberToken;
import com.example.jwt.auth.jwt.request.CreateTokenCommand;
import com.example.jwt.member.MemberRole;
import com.example.jwt.support.AuthFixture;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

class JwtAuthenticationProviderTest {

    JwtProvider jwtProvider = AuthFixture.jwtProvider();
    JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtProvider);

    @Nested
    @DisplayName("authenticate 메서드 실행 시")
    class AuthenticateTest {

        @Test
        @DisplayName("성공")
        void authenticate() {
            //given
            CreateTokenCommand command = new CreateTokenCommand(1L, MemberRole.ROLE_USER);
            MemberToken memberToken = jwtProvider.createToken(command);

            //when
            Authentication authentication = authenticationProvider.authenticate(
                memberToken.accessToken());

            //then
            Object principal = authentication.getPrincipal();
            assertThat(principal.getClass()).isAssignableFrom(JwtAuthentication.class);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                = (UsernamePasswordAuthenticationToken) authentication;
            assertThat(usernamePasswordAuthenticationToken.getAuthorities())
                .containsExactlyElementsOf(
                    MemberRole.ROLE_USER.getAuthorities().stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList());
        }
    }
}