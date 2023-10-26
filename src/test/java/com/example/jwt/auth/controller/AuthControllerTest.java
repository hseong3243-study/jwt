package com.example.jwt.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.jwt.auth.service.response.TokenResponse;
import com.example.jwt.base.BaseControllerTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

class AuthControllerTest extends BaseControllerTest {


    @Autowired
    AuthController authController;

    @Nested
    @DisplayName("로그인 api 호출 시")
    class LoginTest {

        @Test
        @DisplayName("성공")
        void login() throws Exception {
            //given
            TokenResponse response = new TokenResponse("accessToken", "refreshToken");
            given(authService.login(any())).willReturn(response);

            //when
            ResultActions resultActions = mockMvc.perform(post("/api/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(response)));

            //then
            resultActions.andExpect(status().isOk())
                .andDo(print());
        }
    }
}