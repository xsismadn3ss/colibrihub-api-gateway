package com.grupo3.gateway.service.impl;

import com.grupo3.gateway.service.ITokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Service
public class TokenServiceImpl implements ITokenService {
    @Value("${app.jwt.secret}")
    private String secret;

    private Key signingKey(){
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = Jwts.parser()
                .verifyWith((SecretKey) signingKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return resolver.apply(claims);
    }

    @Override
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public void validateToken(String token) {
        String username = extractUsername(token);
        if(username == null){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token invalido");
        }
        if(isExpired(token)){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token expirado");
        }
    }

    @Override
    public Boolean isExpired(String token) {
        Date exp = extractClaim(token, Claims::getExpiration);
        return exp.before(new Date());
    }
}
