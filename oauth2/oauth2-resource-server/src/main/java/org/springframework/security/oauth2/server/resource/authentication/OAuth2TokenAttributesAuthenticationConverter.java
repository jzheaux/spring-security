/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2TokenAttributes;

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUED_AT;

public class OAuth2TokenAttributesAuthenticationConverter
		implements Converter<OAuth2TokenAttributes, AbstractAuthenticationToken> {

	private static final String SCOPE = "scope";

	@Override
	public AbstractAuthenticationToken convert(OAuth2TokenAttributes source) {
		Instant iat = source.getAttribute(ISSUED_AT);
		Instant exp = source.getAttribute(EXPIRES_AT);
		OAuth2AccessToken accessToken  = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, source.getToken(), iat, exp);
		Collection<GrantedAuthority> authorities = extractAuthorities(source);
		return new OAuth2IntrospectionAuthenticationToken(accessToken, source, authorities);
	}

	private Collection<GrantedAuthority> extractAuthorities(OAuth2TokenAttributes attributes) {
		Collection<String> scopes = attributes.getAttribute(SCOPE);
		return Optional.ofNullable(scopes).orElse(Collections.emptyList())
				.stream()
				.map(authority -> new SimpleGrantedAuthority("SCOPE_" + authority))
				.collect(Collectors.toList());
	}
}
