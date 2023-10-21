package com.example.jwt.auth.jwt.request;

import com.example.jwt.auth.MemberRole;

public record CreateTokenCommand(Long memberId, MemberRole memberRole) {

}
