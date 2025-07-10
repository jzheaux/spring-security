package org.springframework.security.core.authority;

import java.util.Collection;
import java.util.function.Consumer;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public interface AuthoritiesContainer {

	Collection<? extends GrantedAuthority> getAuthorities();

	Authentication authorities(Consumer<Collection<GrantedAuthority>> authorities);

	default Authentication authorities(Collection<GrantedAuthority> authorities) {
		return authorities((a) -> {
			a.clear();
			a.addAll(authorities);
		});
	}
}
