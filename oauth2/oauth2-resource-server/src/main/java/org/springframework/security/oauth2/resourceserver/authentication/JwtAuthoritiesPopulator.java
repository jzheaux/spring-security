/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.resourceserver.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthoritiesPopulator;
import org.springframework.security.oauth2.core.scope.ScopeClaimAccessor;
import org.springframework.security.oauth2.core.scope.ScopeGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

/**
 * Populates an {@link JwtAccessTokenAuthenticationToken} with authorities based
 * on any scopes it can find from the provided {@link Authentication}.
 *
 * @author Josh Cummings
 * @since 5.1
 */
public class JwtAuthoritiesPopulator implements OAuth2AuthoritiesPopulator {
	private String scopeAttributeName = ScopeClaimAccessor.DEFAULT_SCOPE_ATTRIBUTE_NAME;

	@Override
	public Authentication populateAuthorities(Authentication authentication) {
		if ( authentication instanceof JwtAccessTokenAuthenticationToken) {
			Jwt jwt = ((JwtAccessTokenAuthenticationToken) authentication).getJwt();

			Collection<GrantedAuthority> authorities =
					this.getScopes(jwt)
						.stream()
						.map(ScopeGrantedAuthority::new)
						.collect(Collectors.toList());

			JwtAccessTokenAuthenticationToken token = new JwtAccessTokenAuthenticationToken(jwt, authorities);
			token.setScopeAttributeName(this.scopeAttributeName);

			return token;
		} else {
			return authentication;
		}
	}

	public void setScopeAttributeName(String scopeAttributeName) {
		Assert.notNull(scopeAttributeName, "scopeAttributeName cannot be null");
		this.scopeAttributeName = scopeAttributeName;
	}

	private Collection<String> getScopes(Jwt jwt) {
		Object scopes = jwt.getClaims().get(this.scopeAttributeName);

		if ( scopes instanceof String ) {
			return Arrays.asList(((String) scopes).split(" "));
		} else if ( scopes instanceof Collection ) {
			return (Collection<String>) scopes;
		}

		return Collections.emptyList();
	}
}
