package com.example.jwt.auth.jwt;

import com.example.jwt.auth.jwt.request.CreateTokenCommand;
import com.example.jwt.auth.jwt.response.CustomClaims;
import com.example.jwt.auth.jwt.response.MemberToken;

public interface JwtProvider {

    MemberToken createToken(CreateTokenCommand command);

    CustomClaims parseToken(String token);
}
