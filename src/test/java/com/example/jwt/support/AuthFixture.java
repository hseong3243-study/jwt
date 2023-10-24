package com.example.jwt.support;

import com.example.jwt.auth.jwt.JJwtProvider;
import com.example.jwt.auth.jwt.JwtProvider;

public final class AuthFixture {

    private static final String ISSUER = "issuer";
    private static final int EXPIRY_SECONDS = 1000;
    private static final String TEST_SECRET = "}:ASV~lS,%!I:ba^GBR<Q@cJN~!,Y0=zx7Rqwum+remZ>ayhI3$4dX$jx~@9[1F";

    public static JwtProvider jwtProvider() {
        return new JJwtProvider(ISSUER, EXPIRY_SECONDS, TEST_SECRET);
    }
}
