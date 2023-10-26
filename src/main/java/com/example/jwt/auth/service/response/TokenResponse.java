package com.example.jwt.auth.service.response;

import com.example.jwt.auth.jwt.response.MemberToken;

public record TokenResponse(String accessToken, String refreshToken) {

    public static TokenResponse from(MemberToken memberToken) {
        return new TokenResponse(memberToken.accessToken(), memberToken.refreshToken());
    }
}
