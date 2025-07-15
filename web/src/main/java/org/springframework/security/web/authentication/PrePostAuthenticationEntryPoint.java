package org.springframework.security.web.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

public class PrePostAuthenticationEntryPoint implements AuthenticationEntryPoint {
	private final AuthenticationEntryPoint pre;
	private final AuthenticationEntryPoint post;

	public PrePostAuthenticationEntryPoint(AuthenticationEntryPoint pre, AuthenticationEntryPoint post) {
		this.pre = pre;
		this.post = post;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
		Authentication authentication = authException.getAuthenticationRequest();
		if (authentication != null && authentication.isAuthenticated()) {
			this.post.commence(request, response, authException);
		} else {
			this.pre.commence(request, response, authException);
		}
	}
}
