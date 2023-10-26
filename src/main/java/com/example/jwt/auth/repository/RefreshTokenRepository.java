package com.example.jwt.auth.repository;

import com.example.jwt.auth.RefreshToken;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByValue(String refreshToken);
}
