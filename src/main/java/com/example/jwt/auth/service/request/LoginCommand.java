package com.example.jwt.auth.service.request;

public record LoginCommand(String username, String password) {

    public static LoginCommand of(String username, String password) {
        return new LoginCommand(username, password);
    }
}
