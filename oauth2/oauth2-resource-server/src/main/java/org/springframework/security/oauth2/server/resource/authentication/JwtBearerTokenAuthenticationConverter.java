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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * A {@link Converter} that takes a {@link Jwt} and converts it into a
 * {@link BearerTokenAuthentication}.
 *
 * In the process, it will attempt to parse either the "scope" or "scp" attribute,
 * whichever it finds first.
 *
 * It's not intended that this implementation be configured since it is simply an adapter.
 * If you are using, for example, a custom {@link JwtGrantedAuthoritiesConverter}, then
 * it's recommended that you simply create your own {@link Converter} that delegates to
 * your custom {@link JwtGrantedAuthoritiesConverter} and instantiates the appropriate
 * {@link BearerTokenAuthentication}.
 *
 * @author Josh Cummings
 * @since 5.2
 */
public final class JwtBearerTokenAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

	private final JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

	private Converter<Jwt, OAuth2AuthenticatedPrincipal> principalConverter = (jwt) ->
		new DefaultOAuth2AuthenticatedPrincipal(jwt.getSubject(), jwt.getClaims(), Collections.emptyList());

	@Override
	public AbstractAuthenticationToken convert(Jwt jwt) {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(),
				jwt.getIssuedAt(), jwt.getExpiresAt());
		Collection<GrantedAuthority> authorities = this.grantedAuthoritiesConverter.convert(jwt);
		OAuth2AuthenticatedPrincipal principal = this.principalConverter.convert(jwt);
		Collection<GrantedAuthority> userAuthorities = new HashSet<>(principal.getAuthorities());
		authorities.addAll(userAuthorities);
		return new BearerTokenAuthentication(principal, accessToken, authorities);
	}

	public void setJwtPrincipalConverter(Converter<Jwt, OAuth2AuthenticatedPrincipal> principalConverter) {
		this.principalConverter = principalConverter;
	}
}
