package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.authorization.AuthoritiesGranter;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.SimpleAuthoritiesGranter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public interface AuthorizableConfigurer<C> {

	C grants(AuthoritiesGranter granter);

	default C grants(String authority) {
		return grants(new SimpleAuthoritiesGranter(authority));
	}

	C needs(AuthorizationManager<RequestAuthorizationContext> needs);

	default C needs(String authority) {
		return needs(AuthorityAuthorizationManager.hasAuthority(authority));
	}

}
