package com.example.jwt.base;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.example.jwt.auth.JwtAuthenticationProvider;
import com.example.jwt.auth.jwt.JwtProvider;
import com.example.jwt.auth.service.AuthService;
import com.example.jwt.base.BaseControllerTest.WebMvcTestConfig;
import com.example.jwt.config.SecurityConfig;
import com.example.jwt.support.AuthFixture;
import com.example.jwt.support.TestController;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@WebMvcTest
@Import({SecurityConfig.class, TestController.class, WebMvcTestConfig.class})
public abstract class BaseControllerTest {

    protected static final String AUTHORIZATION = "Authorization";
    protected MockMvc mockMvc;

    @Autowired
    protected ObjectMapper objectMapper;

    @MockBean
    protected AuthService authService;

    protected String accessToken = AuthFixture.accessToken();

    @BeforeEach
    void setUp(WebApplicationContext context) {
        this.mockMvc = MockMvcBuilders
            .webAppContextSetup(context)
            .apply(springSecurity())
            .defaultRequest(post("/**").with(csrf()))
            .defaultRequest(patch("/**").with(csrf()))
            .defaultRequest(delete("/**").with(csrf()))
            .build();
    }

    @TestConfiguration
    static class WebMvcTestConfig {

        @Bean
        public JwtProvider jwtProvider() {
            return AuthFixture.jwtProvider();
        }

        @Bean
        public JwtAuthenticationProvider jwtAuthenticationProvider(JwtProvider jwtProvider) {
            return new JwtAuthenticationProvider(jwtProvider);
        }
    }
}
