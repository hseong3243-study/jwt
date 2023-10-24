package com.example.jwt.member;

import java.util.List;
import lombok.Getter;

@Getter
public enum MemberRole {
    ROLE_USER(Constants.ROLE_USER, List.of(Constants.ROLE_USER));

    private final String value;
    private final List<String> authorities;

    MemberRole(String value, List<String> authorities) {
        this.value = value;
        this.authorities = authorities;
    }

    private static class Constants {

        private static final String ROLE_USER = "ROLE_USER";
    }
}
