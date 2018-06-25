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
package org.springframework.security.oauth2.server.resource.authentication;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

/**
 * An {@link AuthenticationProvider} implementation of the OAuth2 Resource Server Bearer Token when using Jwt-encoding
 * <p>
 * <p>
 * This {@link AuthenticationProvider} is responsible for decoding and verifying a Jwt-encoded access token,
 * returning a Jwt claims set as part of the {@see Authentication} statement.
 *
 * @author Josh Cummings
 * @author Joe Grandja
 * @since 5.1
 * @see AuthenticationProvider
 * @see JwtDecoder
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {
	private final JwtDecoder jwtDecoder;

	private static final Collection<String> WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES =
			Arrays.asList("scope", "scp");

	public JwtAuthenticationProvider(JwtDecoder jwtDecoder) {
		Assert.notNull(jwtDecoder, "jwtDecoder cannot be null");

		this.jwtDecoder = jwtDecoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;

		Jwt jwt;
		try {
			jwt = this.jwtDecoder.decode(bearer.getToken());
		} catch (JwtException failed) {
			OAuth2Error invalidRequest = invalidToken(failed.getMessage());
			throw new OAuth2AuthenticationException(invalidRequest, failed);
		}

		Collection<GrantedAuthority> authorities =
				this.getScopes(jwt)
						.stream()
						.map(authority -> "SCOPE_" + authority)
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList());

		JwtAuthenticationToken token = new JwtAuthenticationToken(jwt, authorities);

		token.setDetails(bearer.getDetails());

		return token;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static OAuth2Error invalidToken(String message) {
		return new BearerTokenError(
				BearerTokenErrorCodes.INVALID_TOKEN,
				HttpStatus.UNAUTHORIZED,
				message,
				"https://tools.ietf.org/html/rfc6750#section-3.1");
	}

	private Collection<String> getScopes(Jwt jwt) {
		for ( String attributeName : WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES ) {
			Object scopes = jwt.getClaims().get(attributeName);
			if ( scopes instanceof String ) {
				return Arrays.asList(((String) scopes).split(" "));
			} else if ( scopes instanceof Collection ) {
				return (Collection<String>) scopes;
			}
		}

		return Collections.emptyList();
	}
}
