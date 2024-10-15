package com.example.auth_service.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
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

	public boolean validateToken(String token) {
		try {
			JWT.require(Algorithm.HMAC512(secret.getBytes()))
					.build()
					.verify(token);
			return true;
		} catch (JWTVerificationException exception) {
			return false;
		}
	}

	public String getEmailFromToken(String token) {
		DecodedJWT jwt = JWT.decode(token);
		return jwt.getSubject();
	}
}
