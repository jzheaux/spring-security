/*
 * Copyright 2002-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authorization;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthoritiesContainer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;

public final class AuthoritiesGranterAuthenticationProvider implements AuthenticationManager {

	private final AuthenticationManager authenticationProvider;

	private final AuthoritiesGranter authoritiesGranter;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	public AuthoritiesGranterAuthenticationProvider(AuthenticationManager manager, AuthoritiesGranter granter) {
		this.authenticationProvider = manager;
		this.authoritiesGranter = granter;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication current = this.securityContextHolderStrategy.getContext().getAuthentication();
		Authentication result = this.authenticationProvider.authenticate(authentication);
		if (!(result instanceof AuthoritiesContainer container)) {
			return result;
		}
		container = this.authoritiesGranter.grantAuthorities(container);
		if (current != null && current.isAuthenticated()) {
			container = container.grantedAuthorities((a) -> a.addAll(current.getAuthorities()));
		}
		return (Authentication) container;
	}

	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

}
