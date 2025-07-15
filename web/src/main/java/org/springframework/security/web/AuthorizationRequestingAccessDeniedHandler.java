/*
 * Copyright 2002-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authorization.AuthoritiesGranter;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;

public final class AuthorizationRequestingAccessDeniedHandler implements AccessDeniedHandler {

	private final List<AuthorizationRequestEntry> entries;

	private AccessDeniedHandler delegate = new AccessDeniedHandlerImpl();

	public AuthorizationRequestingAccessDeniedHandler(List<AuthorizationRequestEntry> entries) {
		this.entries = entries;
	}

	public void setDefaultAccessDeniedHandler(AccessDeniedHandler defaultAccessDeniedHandler) {
		this.delegate = defaultAccessDeniedHandler;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException access)
			throws IOException, ServletException {
		if (!(access instanceof AuthorizationDeniedException denied)) {
			this.delegate.handle(request, response, access);
			return;
		}
		if (!(denied.getAuthorizationResult() instanceof AuthorityAuthorizationDecision decision)) {
			this.delegate.handle(request, response, access);
			return;
		}
		for (GrantedAuthority needed : decision.getAuthorities()) {
			for (AuthorizationRequestEntry entry : this.entries) {
				if (entry.granter.grantsAuthority(needed)) {
					InsufficientAuthenticationException iae = new InsufficientAuthenticationException(
							"access denied", access);
					iae.setAuthenticationRequest(denied.getAuthentication());
					entry.requester.commence(request, response, iae);
					return;
				}
			}
		}
		this.delegate.handle(request, response, access);
	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class AuthorizationRequestEntry {

		private final AuthoritiesGranter granter;

		private final AuthenticationEntryPoint requester;

		public AuthorizationRequestEntry(AuthoritiesGranter granter, AuthenticationEntryPoint requester) {
			this.granter = granter;
			this.requester = requester;
		}

	}

	public static class Builder {
		private final List<AuthorizationRequestEntry> entries = new ArrayList<>();

		private Builder() {
		}

		public Builder add(AuthoritiesGranter granter, AuthenticationEntryPoint requester) {
			this.entries.add(new AuthorizationRequestEntry(granter, requester));
			return this;
		}

		public AuthorizationRequestingAccessDeniedHandler build() {
			return new AuthorizationRequestingAccessDeniedHandler(this.entries);
		}
	}
}
