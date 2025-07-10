package org.springframework.security.authorization;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthoritiesContainer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

public final class SimpleAuthoritiesGranter implements AuthoritiesGranter {
	private final Duration grantingTime;
	private final Collection<String> authorities;

	public SimpleAuthoritiesGranter(String... authorities) {
		this.grantingTime = null;
		this.authorities = List.of(authorities);
	}

	public SimpleAuthoritiesGranter(Duration grantingTime, String... authorities) {
		this.grantingTime = grantingTime;
		this.authorities = List.of(authorities);
	}

	@Override
	public Boolean grants(GrantedAuthority authority) {
		return this.authorities.contains(authority.getAuthority());
	}

	@Override
	public Authentication grant(Authentication authentication) {
		Assert.isInstanceOf(AuthoritiesContainer.class, authentication, "authentication must be of type AuthoritiesContainer");
		AuthoritiesContainer container = (AuthoritiesContainer) authentication;
		Instant expiresAt = (this.grantingTime != null) ?
			Instant.now().plus(this.grantingTime) : Instant.MAX;
		return container.authorities((authorities) -> {
			for (String authority : this.authorities) {
				authorities.add(new SimpleGrantedAuthority(authority, expiresAt));
			}
		});
	}

	@Override
	public Boolean isGranted(Authentication authentication) {
		Set<String> authorities = new HashSet<>(this.authorities);
		Instant now = Instant.now();
		for (GrantedAuthority authority : authentication.getAuthorities()) {
			if (authority.getExpiresAt().isBefore(now)) {
				authorities.remove(authority.getAuthority());
			}
		}
		return authorities.isEmpty();
	}
}
