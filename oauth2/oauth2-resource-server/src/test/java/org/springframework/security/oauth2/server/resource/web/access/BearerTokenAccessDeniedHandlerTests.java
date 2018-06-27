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

package org.springframework.security.oauth2.server.resource.web.access;

import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Josh Cummings
 */
public class BearerTokenAccessDeniedHandlerTests {
	private BearerTokenAccessDeniedHandler accessDeniedHandler;
	private AccessDeniedException exception;

	@Before
	public void setUp() {
		this.accessDeniedHandler = new BearerTokenAccessDeniedHandler();
		this.exception = new AccessDeniedException("exception");
	}

	@Test
	public void handleWhenNotOAuth2AuthenticatedThenStatus403() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		Authentication authentication = mock(Authentication.class);
		request.setUserPrincipal(authentication);

		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
	}

	@Test
	public void handleWhenNotOAuth2AuthenticatedAndRealmSetThenStatus403AndAuthHeaderWithRealm() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		Authentication authentication = mock(Authentication.class);
		request.setUserPrincipal(authentication);

		this.accessDeniedHandler.setDefaultRealmName("test");
		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer realm=\"test\"");
	}

	@Test
	public void handleWhenTokenHasNoScopesThenInsufficientScopeError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		AbstractOAuth2TokenAuthenticationToken token = mock(AbstractOAuth2TokenAuthenticationToken.class);
		request.setUserPrincipal(token);
		when(token.getTokenAttributes()).thenReturn(Collections.emptyMap());

		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer error=\"insufficient_scope\", " +
				"error_description=\"The token provided has insufficient scope [] for this request\", " +
				"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"");
	}


	@Test
	public void handleWhenTokenHasScopeAttributeThenInsufficientScopeErrorWithScopes() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		AbstractOAuth2TokenAuthenticationToken token = mock(AbstractOAuth2TokenAuthenticationToken.class);
		request.setUserPrincipal(token);
		Map<String, String> attributes = Maps.newHashMap("scope", "message:read message:write");
		when(token.getTokenAttributes()).thenReturn(attributes);

		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer error=\"insufficient_scope\", " +
				"error_description=\"The token provided has insufficient scope [message:read message:write] for this request\", " +
				"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\", " +
				"scope=\"message:read message:write\"");
	}

	@Test
	public void handleWhenTokenHasEmptyScopeAttributeThenInsufficientScopeError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		AbstractOAuth2TokenAuthenticationToken token = mock(AbstractOAuth2TokenAuthenticationToken.class);
		request.setUserPrincipal(token);
		Map<String, String> attributes = Maps.newHashMap("scope", "");
		when(token.getTokenAttributes()).thenReturn(attributes);

		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer error=\"insufficient_scope\", " +
				"error_description=\"The token provided has insufficient scope [] for this request\", " +
				"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"");
	}

	@Test
	public void handleWhenTokenHasScpAttributeThenInsufficientScopeErrorWithScopes() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		AbstractOAuth2TokenAuthenticationToken token = mock(AbstractOAuth2TokenAuthenticationToken.class);
		request.setUserPrincipal(token);
		Map<String, Object> attributes = Maps.newHashMap("scp", Arrays.asList("message:read", "message:write"));
		when(token.getTokenAttributes()).thenReturn(attributes);

		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer error=\"insufficient_scope\", " +
				"error_description=\"The token provided has insufficient scope [message:read message:write] for this request\", " +
				"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\", " +
				"scope=\"message:read message:write\"");
	}

	@Test
	public void handleWhenTokenHasEmptyScpAttributeThenInsufficientScopeError() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		AbstractOAuth2TokenAuthenticationToken token = mock(AbstractOAuth2TokenAuthenticationToken.class);
		request.setUserPrincipal(token);
		Map<String, Object> attributes = Maps.newHashMap("scp", Collections.emptyList());
		when(token.getTokenAttributes()).thenReturn(attributes);

		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer error=\"insufficient_scope\", " +
				"error_description=\"The token provided has insufficient scope [] for this request\", " +
				"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"");
	}

	@Test
	public void handleWhenTokenHasBothScopeAndScpAttributesTheInsufficientErrorBasedOnScopeAttribute() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		AbstractOAuth2TokenAuthenticationToken token = mock(AbstractOAuth2TokenAuthenticationToken.class);
		request.setUserPrincipal(token);
		Map<String, Object> attributes = Maps.newHashMap("scp", Arrays.asList("message:read", "message:write"));
		attributes.put("scope", "missive:read missive:write");
		when(token.getTokenAttributes()).thenReturn(attributes);

		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer error=\"insufficient_scope\", " +
				"error_description=\"The token provided has insufficient scope [missive:read missive:write] for this request\", " +
				"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\", " +
				"scope=\"missive:read missive:write\"");
	}

	@Test
	public void handleWhenTokenHasScopeAttributeAndRealmIsSetThenInsufficientScopeErrorWithScopesAndRealm() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		AbstractOAuth2TokenAuthenticationToken token = mock(AbstractOAuth2TokenAuthenticationToken.class);
		request.setUserPrincipal(token);
		Map<String, String> attributes = Maps.newHashMap("scope", "message:read message:write");
		when(token.getTokenAttributes()).thenReturn(attributes);

		this.accessDeniedHandler.setDefaultRealmName("test");
		this.accessDeniedHandler.handle(request, response, null);

		assertThat(response.getStatus()).isEqualTo(403);
		assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer realm=\"test\", " +
				"error=\"insufficient_scope\", " +
				"error_description=\"The token provided has insufficient scope [message:read message:write] for this request\", " +
				"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\", " +
				"scope=\"message:read message:write\"");
	}

	@Test
	public void setRealmNameWhenNullRealmNameThenNoExceptionThrown() {
		assertThatCode(() -> this.accessDeniedHandler.setDefaultRealmName(null))
				.doesNotThrowAnyException();
	}
}
