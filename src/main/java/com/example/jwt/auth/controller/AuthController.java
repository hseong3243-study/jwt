package com.example.jwt.auth.controller;

import com.example.jwt.auth.controller.request.LoginRequest;
import com.example.jwt.auth.service.AuthService;
import com.example.jwt.auth.service.request.LoginCommand;
import com.example.jwt.auth.service.response.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(LoginRequest request) {
        LoginCommand command = LoginCommand.of(request.username(), request.password());
        LoginResponse response = authService.login(command);
        return ResponseEntity.ok(response);
    }
}
