package org.springframework.security.core;

import java.util.Collection;

public interface GrantedAuthentication<T> extends Authentication {
	@Override
	default Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities();
	}

	Collection<GrantedAuthority> authorities();

	@Override
	default Object getCredentials() {
		return null;
	}

	@Override
	default Object getDetails() {
		return null;
	}

	@Override
	default Object getPrincipal() {
		return principal();
	}

	T principal();

	@Override
	default boolean isAuthenticated() {
		return true;
	}

	@Override
	default void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		throw new UnsupportedOperationException("setAuthenticated is not supported");
	}

	@Override
	default String getName() {
		return String.valueOf(principal());
	}
}
