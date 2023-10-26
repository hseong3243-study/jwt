package com.example.jwt.auth.jwt.response;

public record MemberToken(String accessToken, String refreshToken) {

    public static MemberToken of(String accessToken, String refreshToken) {
        return new MemberToken(accessToken, refreshToken);
    }
}
