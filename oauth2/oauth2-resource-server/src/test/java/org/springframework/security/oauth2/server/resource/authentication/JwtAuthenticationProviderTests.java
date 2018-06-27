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

import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link JwtAuthenticationProvider}
 *
 * @author Josh Cummings
 */
@RunWith(MockitoJUnitRunner.class)
public class JwtAuthenticationProviderTests {
	@Mock
	JwtDecoder jwtDecoder;

	@Mock
	Jwt jwt;

	JwtAuthenticationProvider provider;

	@Before
	public void setup() {
		this.provider =
				new JwtAuthenticationProvider(this.jwtDecoder);
	}

	@Test
	public void authenticateWhenJwtDecodesThenAuthenticationHasAttributesContainedInJwt() {
		BearerTokenAuthenticationToken token = this.authentication();
		Map<String, Object> claims = new HashMap<>();
		claims.put("name", "value");

		when(this.jwtDecoder.decode("token")).thenReturn(this.jwt);
		when(this.jwt.getClaims()).thenReturn(claims);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		assertThat(authentication.getTokenAttributes()).isEqualTo(claims);
	}

	@Test
	public void authenticateWhenJwtDecodeFailsThenRespondsWithInvalidToken() {
		BearerTokenAuthenticationToken token = this.authentication();

		when(this.jwtDecoder.decode("token")).thenThrow(JwtException.class);

		assertThatThrownBy(() -> this.provider.authenticate(token))
				.matches(failed -> failed instanceof OAuth2AuthenticationException)
				.matches(errorCode(BearerTokenErrorCodes.INVALID_TOKEN));
	}

	@Test
	public void authenticateWhenTokenHasScopeAttributeThenTranslatedToAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		when(this.jwt.getClaims()).thenReturn(Maps.newHashMap("scope", "message:read message:write"));
		when(this.jwtDecoder.decode(token.getToken())).thenReturn(this.jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly(
				new SimpleGrantedAuthority("SCOPE_message:read"),
				new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void authenticateWhenTokenHasEmptyScopeAttributeThenTranslatedToNoAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		when(this.jwt.getClaims()).thenReturn(Maps.newHashMap("scope", ""));
		when(this.jwtDecoder.decode(token.getToken())).thenReturn(this.jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly();
	}

	@Test
	public void authenticateWhenTokenHasScpAttributeThenTranslatedToAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		when(this.jwt.getClaims())
				.thenReturn(Maps.newHashMap("scp", Arrays.asList("message:read", "message:write")));
		when(this.jwtDecoder.decode(token.getToken())).thenReturn(this.jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly(
				new SimpleGrantedAuthority("SCOPE_message:read"),
				new SimpleGrantedAuthority("SCOPE_message:write"));
	}

	@Test
	public void authenticateWhenTokenHasEmptyScpAttributeThenTranslatedToNoAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		when(this.jwt.getClaims())
				.thenReturn(Maps.newHashMap("scp", Arrays.asList()));
		when(this.jwtDecoder.decode(token.getToken())).thenReturn(this.jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly();
	}

	@Test
	public void authenticateWhenTokenHasBothScopeAndScpThenScopeAttributeIsTranslatedToAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		Map<String, Object> claims = Maps.newHashMap("scp", Arrays.asList("message:read", "message:write"));
		claims.put("scope", "missive:read missive:write");

		when(this.jwt.getClaims()).thenReturn(claims);
		when(this.jwtDecoder.decode(token.getToken())).thenReturn(this.jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly(
				new SimpleGrantedAuthority("SCOPE_missive:read"),
				new SimpleGrantedAuthority("SCOPE_missive:write"));
	}

	@Test
	public void authenticateWhenTokenHasEmptyScopeAndNonEmptyScpThenScopeAttributeIsTranslatedToNoAuthorities() {
		BearerTokenAuthenticationToken token = this.authentication();

		Map<String, Object> claims = Maps.newHashMap("scp", Arrays.asList("message:read", "message:write"));
		claims.put("scope", "");

		when(this.jwt.getClaims()).thenReturn(claims);
		when(this.jwtDecoder.decode(token.getToken())).thenReturn(this.jwt);

		JwtAuthenticationToken authentication =
				(JwtAuthenticationToken) this.provider.authenticate(token);

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();

		assertThat(authorities).containsExactly();
	}

	@Test
	public void supportsWhenBearerTokenAuthenticationTokenThenReturnsTrue() {
		assertThat(this.provider.supports(BearerTokenAuthenticationToken.class)).isTrue();
	}

	private BearerTokenAuthenticationToken authentication() {
		return new BearerTokenAuthenticationToken("token");
	}

	private Predicate<? super Throwable> errorCode(String errorCode) {
		return failed ->
				((OAuth2AuthenticationException) failed).getError().getErrorCode() == errorCode;
	}
}
