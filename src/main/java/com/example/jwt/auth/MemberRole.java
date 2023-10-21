package com.example.jwt.auth;

import lombok.Getter;

@Getter
public enum MemberRole {
    USER("user");

    private final String value;

    MemberRole(String value) {
        this.value = value;
    }
}
