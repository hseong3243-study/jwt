package com.example.jwt.auth.jwt;

import com.example.jwt.auth.jwt.request.CreateTokenCommand;

public interface JwtProvider {

    String createToken(CreateTokenCommand command);

    void validateToken(String token);
}
