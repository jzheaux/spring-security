package org.springframework.security.oauth2.client.oidc.web.authentication.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.authentication.logout.InMemoryOidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcProviderSessionRegistry;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

public final class OidcProviderSessionAuthenticationStrategy implements SessionAuthenticationStrategy {
	private OidcProviderSessionRegistry sessions = new InMemoryOidcProviderSessionRegistry();

	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return;
		}
		if (authentication == null) {
			return;
		}
		if (!(authentication.getPrincipal() instanceof OidcUser)) {
			return;
		}
		this.sessions.mapClientSession(((OidcUser) authentication.getPrincipal()).getIdToken(), session.getId());
	}
}
