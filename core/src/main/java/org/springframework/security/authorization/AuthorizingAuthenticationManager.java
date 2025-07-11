package org.springframework.security.authorization;

import java.util.function.Supplier;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthoritiesContainer;

public final class AuthorizingAuthenticationManager implements AuthenticationManager, AuthorizationManager<Authentication> {
	private final AuthoritiesGranter authoritiesGranter;
	private final AuthenticationManager authenticationManager;

	public AuthorizingAuthenticationManager(AuthoritiesGranter authoritiesGranter, AuthenticationManager authenticationManager) {
		this.authoritiesGranter = authoritiesGranter;
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication result = this.authenticationManager.authenticate(authentication);
		Authentication granted = this.authoritiesGranter.grant(result);
		if (granted instanceof AuthoritiesContainer authoritiesContainer) {
			return authoritiesContainer.authorities((a) -> a.addAll(authentication.getAuthorities()));
		}
		return granted;
	}

	@Override
	public AuthorizationResult authorize(Supplier<Authentication> authentication, Authentication object) {
		return new AuthorizationDecision(this.authoritiesGranter.isGranted(object));
	}
}
