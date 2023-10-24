package com.example.jwt.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.then;

import com.example.jwt.auth.jwt.JwtProvider;
import com.example.jwt.auth.jwt.request.CreateTokenCommand;
import com.example.jwt.member.MemberRole;
import com.example.jwt.support.AuthFixture;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    JwtProvider jwtProvider = AuthFixture.jwtProvider();
    JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(
        jwtProvider);
    JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(
        jwtAuthenticationProvider);

    MockHttpServletRequest mockRequest = new MockHttpServletRequest();
    MockHttpServletResponse mockResponse = new MockHttpServletResponse();

    @Mock
    FilterChain filterChain;

    @Nested
    @DisplayName("doFilter 메서드 실행 시")
    class DoFilterTest {

        @Test
        @DisplayName("성공: 다음 필터를 호출한다.")
        void doFilter() throws ServletException, IOException {
            //given
            //when
            jwtAuthenticationFilter.doFilter(mockRequest, mockResponse, filterChain);

            //then
            then(filterChain).should().doFilter(any(), any());
        }

        @Test
        @DisplayName("성공: 액세스 토큰이 요청에 포함된 경우")
        void doFilterWhenContainsToken() throws ServletException, IOException {
            //given
            CreateTokenCommand command = new CreateTokenCommand(1L, MemberRole.ROLE_USER);
            String accessToken = jwtProvider.createToken(command);
            mockRequest.addHeader("Authorization", accessToken);

            //when
            jwtAuthenticationFilter.doFilter(mockRequest, mockResponse, filterChain);

            //then
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication).isNotNull();
        }

        @Test
        @DisplayName("성공: 액세스 토큰이 요청에 포함되지 않은 경우")
        void doFilterWhenNotContainsToken() throws ServletException, IOException {
            //given
            //when
            jwtAuthenticationFilter.doFilter(mockRequest, mockResponse, filterChain);

            //then
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication).isNull();
        }
    }
}