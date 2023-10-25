package com.example.jwt.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import com.example.jwt.auth.jwt.JwtProvider;
import com.example.jwt.auth.service.request.LoginCommand;
import com.example.jwt.auth.service.response.LoginResponse;
import com.example.jwt.member.Member;
import com.example.jwt.member.repository.MemberRepository;
import com.example.jwt.support.AuthFixture;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    MemberRepository memberRepository;

    @InjectMocks
    AuthService authService;

    @Spy
    PasswordEncoder mockPasswordEncoder = new PasswordEncoder() {
        @Override
        public String encode(CharSequence rawPassword) {
            return new StringBuilder(rawPassword).reverse().toString();
        }

        @Override
        public boolean matches(CharSequence rawPassword, String encodedPassword) {
            return new StringBuilder(rawPassword).reverse().toString().equals(encodedPassword);
        }
    };

    @Spy
    JwtProvider jwtProvider = AuthFixture.jwtProvider();

    @Nested
    @DisplayName("login 메서드 실행 시")
    class LoginTest {

        LoginCommand loginCommand = new LoginCommand("username", "password");
        Member member = new Member(loginCommand.username(), loginCommand.password());

        @Test
        @DisplayName("성공")
        void success() {
            //given
            ReflectionTestUtils.setField(member, "memberId", 1L);

            given(memberRepository.findByUsername(any())).willReturn(Optional.ofNullable(member));

            //when
            LoginResponse response = authService.login(loginCommand);

            //then
            assertThat(response.accessToken()).isNotBlank();
        }
    }
}