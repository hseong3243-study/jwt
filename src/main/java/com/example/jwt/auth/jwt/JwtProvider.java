package com.example.jwt.auth.jwt;

import com.example.jwt.auth.jwt.request.CreateTokenCommand;
import com.example.jwt.auth.jwt.response.CustomClaims;

public interface JwtProvider {

    MemberToken createToken(CreateTokenCommand command);

    CustomClaims parseToken(String token);
}
