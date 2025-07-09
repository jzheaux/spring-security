package org.springframework.security.web;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
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
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException access) throws IOException, ServletException {
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
				if (entry.granter.grants(needed)) {
					entry.requester.commence(request, response, null);
					return;
				}
			}
		}
		this.delegate.handle(request, response, access);
	}

	public static final class AuthorizationRequestEntry {
		private final AuthoritiesGranter granter;
		private final AuthenticationEntryPoint requester;

		public AuthorizationRequestEntry(AuthoritiesGranter granter, AuthenticationEntryPoint requester) {
			this.granter = granter;
			this.requester = requester;
		}
	}
}
