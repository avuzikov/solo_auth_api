package com.example.auth_service.controller;

import com.example.auth_service.config.SecurityConfig;
import com.example.auth_service.model.User;
import com.example.auth_service.repository.UserRepository;
import com.example.auth_service.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
public class AuthControllerTests {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private UserRepository userRepository;

	@MockBean
	private PasswordEncoder passwordEncoder;

	@MockBean
	private JwtUtil jwtUtil;

	@Autowired
	private ObjectMapper objectMapper;

	private User testUser;

	@BeforeEach
	void setUp() {
		testUser = new User();
		testUser.setName("Test User");
		testUser.setEmail("test@example.com");
		testUser.setPassword("password123");
	}

	@Test
	void checkStatus_shouldReturnOk() throws Exception {
		mockMvc.perform(get("/account"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("Auth service is up and running"));
	}

	@Test
	void registerUser_withNewEmail_shouldReturnOk() throws Exception {
		when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.empty());
		when(passwordEncoder.encode(testUser.getPassword())).thenReturn("encodedPassword");
		when(userRepository.save(any(User.class))).thenReturn(testUser);

		mockMvc.perform(post("/account/register")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(testUser)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.message").value("User registered successfully"));
	}

	@Test
	void registerUser_withExistingEmail_shouldReturnBadRequest() throws Exception {
		when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));

		mockMvc.perform(post("/account/register")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(testUser)))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("Email already exists"));
	}

	@Test
	void getToken_withValidCredentials_shouldReturnToken() throws Exception {
		when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
		when(passwordEncoder.matches(testUser.getPassword(), testUser.getPassword())).thenReturn(true);
		when(jwtUtil.generateToken(testUser.getEmail())).thenReturn("test.jwt.token");

		Map<String, String> credentials = new HashMap<>();
		credentials.put("email", testUser.getEmail());
		credentials.put("password", testUser.getPassword());

		mockMvc.perform(post("/account/token")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(credentials)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.token").value("test.jwt.token"));
	}

	@Test
	void getToken_withInvalidCredentials_shouldReturnBadRequest() throws Exception {
		when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
		when(passwordEncoder.matches(testUser.getPassword(), testUser.getPassword())).thenReturn(false);

		Map<String, String> credentials = new HashMap<>();
		credentials.put("email", testUser.getEmail());
		credentials.put("password", "wrongpassword");

		mockMvc.perform(post("/account/token")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(credentials)))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("Invalid credentials"));
	}
}
