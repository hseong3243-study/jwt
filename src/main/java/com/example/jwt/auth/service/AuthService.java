package com.example.jwt.auth.service;

import static com.example.jwt.member.MemberRole.ROLE_USER;

import com.example.jwt.auth.RefreshToken;
import com.example.jwt.auth.jwt.JwtProvider;
import com.example.jwt.auth.jwt.response.MemberToken;
import com.example.jwt.auth.jwt.request.CreateTokenCommand;
import com.example.jwt.auth.repository.RefreshTokenRepository;
import com.example.jwt.auth.service.request.LoginCommand;
import com.example.jwt.auth.service.response.LoginResponse;
import com.example.jwt.member.Member;
import com.example.jwt.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    public LoginResponse login(LoginCommand command) {
        Member member = memberRepository.findByUsername(command.username())
            .orElseThrow(() -> new IllegalArgumentException("아이디/비밀번호가 일치하지 않습니다."));
        matchesPassword(command.password(), member.getPassword());
        CreateTokenCommand createTokenCommand = CreateTokenCommand.of(member.getMemberId(),
            ROLE_USER);
        MemberToken memberToken = jwtProvider.createToken(createTokenCommand);
        refreshTokenRepository.save(new RefreshToken(memberToken.refreshToken()));
        return LoginResponse.from(memberToken);
    }

    private void matchesPassword(String rawPassword, String encodedPassword) {
        if (passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new IllegalArgumentException("아이디/비밀번호가 일치하지 않습니다.");
        }
    }
}
