package org.springframework.security.authorization;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public interface AuthoritiesGranter {
	boolean grants(GrantedAuthority authority);

	Authentication grant(Authentication authentication);
}
