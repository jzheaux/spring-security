package org.springframework.security.web.access;

import java.util.function.Supplier;

import org.springframework.security.authorization.AuthoritiesGranter;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class AuthoritiesGranterAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
	private final AuthoritiesGranter granter;

	public AuthoritiesGranterAuthorizationManager(AuthoritiesGranter granter) {
		this.granter = granter;
	}

	@Override
	public AuthorizationResult authorize(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
		return new AuthorizationDecision(this.granter.isGranted(authentication.get()));
	}
}
