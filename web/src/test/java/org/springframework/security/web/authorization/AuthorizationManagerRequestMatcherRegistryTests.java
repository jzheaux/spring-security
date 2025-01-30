package org.springframework.security.web.authorization;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;

import static org.springframework.security.authorization.AuthenticatedAuthorizationManager.authenticated;
import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;
import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole;
import static org.springframework.security.web.servlet.util.matcher.ServletRequestMatcherBuilders.servletPath;

class AuthorizationManagerRequestMatcherRegistryTests {

	@Test
	void demo() {
		AuthorizationManagerRequestMatcherRegistry registry = new AuthorizationManagerRequestMatcherRegistry();
		registry.allow().anyRequest();
		registry.allow().requests("/endpoint/**", "/api/**");
		registry.allow().requests(HttpMethod.GET, "/gets/**");
		registry.allow(authenticated()).requests(HttpMethod.POST, "/posts/**");
		registry.allow(authenticated()).anyRequest();
		registry.allow(hasRole("USER")).requests("/user/**");
		registry.allow(hasAuthority("SCOPE_message:read")).requests("/message/**");
		registry.allow(hasAuthority("servlet")).requests(servletPath("/path").matcher("/subpath/**"));
		registry.deny().anyRequest();
		registry.deny().requests("/denied/**");
		registry.deny(hasRole("USER")).requests("/no-users/**");

	}
}
