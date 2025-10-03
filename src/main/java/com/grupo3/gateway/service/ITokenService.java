package com.grupo3.gateway.service;

public interface ITokenService {
    String extractUsername(String token);
    void validateToken(String token);
    Boolean isExpired(String token);
}
