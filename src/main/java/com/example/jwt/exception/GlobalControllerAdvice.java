package com.example.jwt.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalControllerAdvice {

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ErrorResponse> runtimeEx(RuntimeException ex) {
        ErrorResponse exceptionResponse = new ErrorResponse("예측하지 못한 문제가 발생하였습니다.");
        return ResponseEntity.internalServerError().body(exceptionResponse);
    }
}
