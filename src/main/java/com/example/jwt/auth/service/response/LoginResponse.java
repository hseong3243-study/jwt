package com.example.jwt.auth.service.response;

import com.example.jwt.auth.jwt.response.MemberToken;

public record LoginResponse(String accessToken, String refreshToken) {

    public static LoginResponse from(MemberToken memberToken) {
        return new LoginResponse(memberToken.accessToken(), memberToken.refreshToken());
    }
}
