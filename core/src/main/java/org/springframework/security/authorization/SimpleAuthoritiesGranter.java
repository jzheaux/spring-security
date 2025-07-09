package org.springframework.security.authorization;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthoritiesContainer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

public final class SimpleAuthoritiesGranter implements AuthoritiesGranter {
	private final Collection<String> authorities;

	public SimpleAuthoritiesGranter(String... authorities) {
		this.authorities = List.of(authorities);
	}

	@Override
	public boolean grants(GrantedAuthority authority) {
		return this.authorities.contains(authority.getAuthority());
	}

	@Override
	public Authentication grant(Authentication authentication) {
		Assert.isInstanceOf(AuthoritiesContainer.class, authentication, "authentication must be of type AuthoritiesContainer");
		AuthoritiesContainer container = (AuthoritiesContainer) authentication;
		return container.authorities((authorities) -> {
			for (String authority : this.authorities) {
				authorities.add(new SimpleGrantedAuthority(authority));
			}
		});
	}
}
