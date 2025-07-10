package org.springframework.security.authorization;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public interface AuthoritiesGranter {
	
	Authentication grant(Authentication authentication);

	default Boolean grants(GrantedAuthority authority) {
		return null;
	}

	default Boolean isGranted(Authentication authentication) {
		if (!authentication.isAuthenticated()) {
			return false;
		}
		Collection<GrantedAuthority> valid = new HashSet<>();
		Instant now = Instant.now();
		for (GrantedAuthority authority : authentication.getAuthorities()) {
			if (authority.getExpiresAt().isAfter(now)) {
				valid.add(authority);
			}
		}
		Set<GrantedAuthority> granted = new HashSet<>(grant(authentication).getAuthorities());
		return granted.equals(valid);
	}
}
