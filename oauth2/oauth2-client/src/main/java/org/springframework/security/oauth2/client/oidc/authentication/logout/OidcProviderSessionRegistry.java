package org.springframework.security.oauth2.client.oidc.authentication.logout;

import java.util.Collection;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

public interface OidcProviderSessionRegistry extends SessionAuthenticationStrategy {

	@Override
	default void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
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
		mapClientSession(((OidcUser) authentication.getPrincipal()).getIdToken(), session.getId());
	}

	void mapClientSession(OidcIdToken token, String clientSessionId);

	Collection<String> getClientSessions(OidcLogoutToken token);
}
