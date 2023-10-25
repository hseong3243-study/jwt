package com.example.jwt.support;

import com.example.jwt.auth.resolver.LoginUser;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {

    @GetMapping("/login-user")
    public ResponseEntity<Long> loginUser(@LoginUser Long memberId) {
        return ResponseEntity.ok(memberId);
    }
}
