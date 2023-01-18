package org.springframework.security.oauth2.client.oidc.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.context.ApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.session.SessionIdChangedEvent;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcLogoutToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionCreatedEvent;

public interface OidcSessionRegistry extends SessionAuthenticationStrategy, ApplicationListener<AbstractSessionEvent> {

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
		registerSession(((OidcUser) authentication.getPrincipal()).getIdToken(), session.getId());
	}

	void registerSession(OidcIdToken token, String sessionId);

	void invalidateSessions(OidcLogoutToken token);

	@Override
	default
	void onApplicationEvent(AbstractSessionEvent event) {
		if (event instanceof SessionDestroyedEvent) {
			SessionDestroyedEvent sessionDestroyedEvent = (SessionDestroyedEvent) event;
			List<SecurityContext> contexts = ((SessionDestroyedEvent) event).getSecurityContexts();

			String sessionId = sessionDestroyedEvent.getId();
			removeSessionInformation(sessionId);
		}
		else if (event instanceof SessionIdChangedEvent) {
			SessionIdChangedEvent sessionIdChangedEvent = (SessionIdChangedEvent) event;
			String oldSessionId = sessionIdChangedEvent.getOldSessionId();
			if (this.sessionIds.containsKey(oldSessionId)) {
				Object principal = this.sessionIds.get(oldSessionId).getPrincipal();
				removeSessionInformation(oldSessionId);
				registerNewSession(sessionIdChangedEvent.getNewSessionId(), principal);
			}
		}
	}
}
