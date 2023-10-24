package com.example.jwt.auth.service.response;

public record LoginResponse(String accessToken) {

    public static LoginResponse from(String accessToken) {
        return new LoginResponse(accessToken);
    }
}
