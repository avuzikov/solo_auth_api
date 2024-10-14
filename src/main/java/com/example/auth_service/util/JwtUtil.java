package com.example.auth_service.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtil {

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private long expiration;

	public String generateToken(String email) {
		return JWT.create()
				.withSubject(email)
				.withExpiresAt(new Date(System.currentTimeMillis() + expiration))
				.sign(Algorithm.HMAC512(secret.getBytes()));
	}
}
