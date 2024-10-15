package com.example.auth_service.controller;

import com.example.auth_service.model.User;
import com.example.auth_service.repository.UserRepository;
import com.example.auth_service.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/account")
public class AuthController {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JwtUtil jwtUtil;

	@GetMapping
	public ResponseEntity<Object> checkStatus() {
		Map<String, String> response = new HashMap<>();
		response.put("status", "Auth service is up and running");
		return ResponseEntity.ok(response);
	}

	@PostMapping("/register")
	public ResponseEntity<Object> registerUser(@RequestBody User user) {
		if (userRepository.findByEmail(user.getEmail()).isPresent()) {
			Map<String, String> response = new HashMap<>();
			response.put("error", "Email already exists");
			return ResponseEntity.badRequest().body(response);
		}

		user.setPassword(passwordEncoder.encode(user.getPassword()));
		User savedUser = userRepository.save(user);
		Map<String, String> response = new HashMap<>();
		response.put("message", "User registered successfully");
		return ResponseEntity.ok(response);
	}

	@PostMapping("/token")
	public ResponseEntity<Object> getToken(@RequestBody Map<String, String> credentials) {
		String email = credentials.get("email");
		String password = credentials.get("password");

		return userRepository.findByEmail(email)
				.filter(user -> passwordEncoder.matches(password, user.getPassword()))
				.map(user -> {
					String token = jwtUtil.generateToken(email);
					Map<String, String> response = new HashMap<>();
					response.put("token", token);
					return ResponseEntity.ok((Object) response);
				})
				.orElseGet(() -> {
					Map<String, String> response = new HashMap<>();
					response.put("error", "Invalid credentials");
					return ResponseEntity.badRequest().body(response);
				});
	}

	@PostMapping("/validate")
	public ResponseEntity<Object> validateToken(@RequestHeader("Authorization") String authHeader) {
		String token = null;
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			token = authHeader.substring(7);
		}

		if (token == null) {
			Map<String, Object> response = new HashMap<>();
			response.put("valid", false);
			response.put("error", "No token provided");
			return ResponseEntity.badRequest().body(response);
		}

		boolean isValid = jwtUtil.validateToken(token);
		Map<String, Object> response = new HashMap<>();
		response.put("valid", isValid);

		if (isValid) {
			String email = jwtUtil.getEmailFromToken(token);
			response.put("email", email);
		}

		return ResponseEntity.ok(response);
	}

}