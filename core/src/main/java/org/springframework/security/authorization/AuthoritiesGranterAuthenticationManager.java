package org.springframework.security.authorization;

import java.util.function.Function;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class AuthoritiesGranterAuthenticationManager implements AuthenticationManager, AuthenticationProvider {
	private final Function<Class<?>, Boolean> supports;

	private final AuthenticationManager authenticationManager;

	private final AuthoritiesGranter authoritiesGranter;

	public AuthoritiesGranterAuthenticationManager(Function<Class<?>, Boolean> supports, AuthenticationManager authenticationManager, AuthoritiesGranter authoritiesGranter) {
		this.supports = supports;
		this.authenticationManager = authenticationManager;
		this.authoritiesGranter = authoritiesGranter;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication result = this.authenticationManager.authenticate(authentication);
		return this.authoritiesGranter.grant(result);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return this.supports.apply(authentication);
	}
}
