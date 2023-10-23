package com.example.jwt.auth.jwt.request;

import com.example.jwt.member.MemberRole;

public record CreateTokenCommand(Long memberId, MemberRole memberRole) {

    public static CreateTokenCommand of(Long memberId, MemberRole memberRole) {
        return new CreateTokenCommand(memberId, memberRole);
    }
}
