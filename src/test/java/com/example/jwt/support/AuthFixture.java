package com.example.jwt.support;

import com.example.jwt.auth.jwt.JJwtProvider;
import com.example.jwt.auth.jwt.JwtProvider;
import com.example.jwt.auth.jwt.MemberToken;
import com.example.jwt.auth.jwt.request.CreateTokenCommand;
import com.example.jwt.member.MemberRole;

public final class AuthFixture {

    private static final String ISSUER = "issuer";
    private static final int EXPIRY_SECONDS = 1000;
    private static final int REFRESH_EXPIRY_SECONDS = 10000;
    private static final String TEST_SECRET = "}:ASV~lS,%!I:ba^GBR<Q@cJN~!,Y0=zx7Rqwum+remZ>ayhI3$4dX$jx~@9[1F";
    private static final String TEST_REFRESH_SECRET = "~GWW.|?:\"#Rqmm^-nk#>#4Ngc}]3xz!hOQCXNF:8z-Mdn\"U!Vt</+/8;ATR*lc{";
    private static final Long MEMBER_ID = 1L;
    private static final MemberRole MEMBER_ROLE = MemberRole.ROLE_USER;


    public static JwtProvider jwtProvider() {
        return jJwtProvider();
    }

    public static JJwtProvider jJwtProvider() {
        return new JJwtProvider(ISSUER, EXPIRY_SECONDS, REFRESH_EXPIRY_SECONDS, TEST_SECRET,
            TEST_REFRESH_SECRET);
    }

    public static String accessToken() {
        CreateTokenCommand command = new CreateTokenCommand(MEMBER_ID, MEMBER_ROLE);
        MemberToken memberToken = jwtProvider().createToken(command);
        return memberToken.accessToken();
    }
}
