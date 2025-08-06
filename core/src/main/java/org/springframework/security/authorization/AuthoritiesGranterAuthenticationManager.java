/*
 * Copyright 2004-present the original author or authors.
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

import java.util.Collection;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;

public final class AuthoritiesGranterAuthenticationManager implements AuthenticationManager {

	private final AuthenticationManager authenticationManager;

	private final AuthoritiesGranter authoritiesGranter;

	private final CurrentAuthoritiesMergingAuthoritiesGranter merge = new CurrentAuthoritiesMergingAuthoritiesGranter();

	public AuthoritiesGranterAuthenticationManager(AuthenticationManager manager, AuthoritiesGranter granter) {
		this.authenticationManager = manager;
		this.authoritiesGranter = granter;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication result = this.authenticationManager.authenticate(authentication);
		result = this.authoritiesGranter.grantAuthorities(result);
		return this.merge.grantAuthorities(result);
	}

	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.merge.setSecurityContextHolderStrategy(securityContextHolderStrategy);
	}

	private static final class CurrentAuthoritiesMergingAuthoritiesGranter implements AuthoritiesGranter {

		private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

		@Override
		public Authentication grantAuthorities(Authentication authentication) {
			Authentication current = this.securityContextHolderStrategy.getContext().getAuthentication();
			if (current != null && current.isAuthenticated()) {
				Collection<GrantedAuthority> toGrant = authentication.getGrantedAuthorities();
				Collection<GrantedAuthority> existing = current.getGrantedAuthorities();
				existing.addAll(toGrant);
				return current.withGrantedAuthorities(existing);
			}
			return authentication;
		}

		void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
			this.securityContextHolderStrategy = securityContextHolderStrategy;
		}

	}

}
