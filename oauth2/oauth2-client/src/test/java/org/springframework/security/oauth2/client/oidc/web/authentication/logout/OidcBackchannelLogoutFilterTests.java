/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.web.authentication.logout;

import java.util.Date;
import java.util.Set;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.client.oidc.web.authentication.session.OidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

public class OidcBackchannelLogoutFilterTests {

	@Test
	public void doFilterRequestDoesNotMatchThenDoesNotRun() throws Exception {
		ClientRegistrationRepository clients = mock(ClientRegistrationRepository.class);
		JwtDecoderFactory<ClientRegistration> factory = mock(JwtDecoderFactory.class);
		OidcBackchannelLogoutFilter filter = new OidcBackchannelLogoutFilter(clients, factory);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verifyNoInteractions(clients, factory);
		verify(chain).doFilter(request, response);
	}

	@Test
	public void doFilterRequestDoesNotMatchContainLogoutTokenThenDoesNotRun() throws Exception {
		ClientRegistrationRepository clients = mock(ClientRegistrationRepository.class);
		JwtDecoderFactory<ClientRegistration> factory = mock(JwtDecoderFactory.class);
		OidcBackchannelLogoutFilter filter = new OidcBackchannelLogoutFilter(clients, factory);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/id/logout");
		request.setServletPath("/oauth2/id/logout");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verifyNoInteractions(clients, factory);
		verify(chain).doFilter(request, response);
	}

	@Test
	public void doFilterWithNoMatchingClientThenDoesNotRun() throws Exception {
		ClientRegistrationRepository clients = mock(ClientRegistrationRepository.class);
		JwtDecoderFactory<ClientRegistration> factory = mock(JwtDecoderFactory.class);
		OidcBackchannelLogoutFilter filter = new OidcBackchannelLogoutFilter(clients, factory);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/id/logout");
		request.setServletPath("/oauth2/id/logout");
		request.setParameter("logout_token", "logout_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verify(clients).findByRegistrationId("id");
		verifyNoInteractions(factory);
		verify(chain).doFilter(request, response);
	}

	@Test
	public void doFilterWithSessionMatchingLogoutTokenThenInvalidates() throws Exception {
		ClientRegistration registration = TestClientRegistrations.clientRegistration().build();
		ClientRegistrationRepository clients = mock(ClientRegistrationRepository.class);
		given(clients.findByRegistrationId(any())).willReturn(registration);
		JwtDecoderFactory<ClientRegistration> factory = mock(JwtDecoderFactory.class);
		JwtDecoder jwtDecoder = mock(JwtDecoder.class);
		given(factory.createDecoder(any())).willReturn(jwtDecoder);
		Jwt jwt = TestJwts.jwt().claim("sid", "provider").build();
		given(jwtDecoder.decode(any())).willReturn(jwt);
		OidcProviderSessionRegistry registry = mock(OidcProviderSessionRegistry.class);
		Set<SessionInformation> infos = Set.of(new SessionInformation(new Object(), "clientOne", new Date()),
				new SessionInformation(new Object(), "clientTwo", new Date()));
		given(registry.unregister(any())).willReturn(infos);
		SessionInformationExpiredStrategy strategy = mock(SessionInformationExpiredStrategy.class);
		OidcBackchannelLogoutFilter filter = new OidcBackchannelLogoutFilter(clients, factory);
		filter.setProviderSessionRegistry(registry);
		filter.setExpiredStrategy(strategy);
		MockHttpServletRequest request = new MockHttpServletRequest("POST",
				"/oauth2/" + registration.getRegistrationId() + "/logout");
		request.setServletPath("/oauth2/id/logout");
		request.setParameter("logout_token", "logout_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verify(strategy, times(2)).onExpiredSessionDetected(any());
		verifyNoInteractions(chain);
		assertThat(response.getStatus()).isEqualTo(200);
	}

	@Test
	public void doFilterWhenInvalidJwtThenBadRequest() throws Exception {
		ClientRegistration registration = TestClientRegistrations.clientRegistration().build();
		ClientRegistrationRepository clients = mock(ClientRegistrationRepository.class);
		given(clients.findByRegistrationId(any())).willReturn(registration);
		JwtDecoderFactory<ClientRegistration> factory = mock(JwtDecoderFactory.class);
		JwtDecoder jwtDecoder = mock(JwtDecoder.class);
		given(factory.createDecoder(any())).willReturn(jwtDecoder);
		given(jwtDecoder.decode(any())).willThrow(new BadJwtException("bad"));
		OidcProviderSessionRegistry registry = mock(OidcProviderSessionRegistry.class);
		Set<SessionInformation> infos = Set.of(new SessionInformation(new Object(), "clientOne", new Date()),
				new SessionInformation(new Object(), "clientTwo", new Date()));
		given(registry.unregister(any())).willReturn(infos);
		SessionInformationExpiredStrategy strategy = mock(SessionInformationExpiredStrategy.class);
		OidcBackchannelLogoutFilter filter = new OidcBackchannelLogoutFilter(clients, factory);
		filter.setProviderSessionRegistry(registry);
		filter.setExpiredStrategy(strategy);
		MockHttpServletRequest request = new MockHttpServletRequest("POST",
				"/oauth2/" + registration.getRegistrationId() + "/logout");
		request.setServletPath("/oauth2/id/logout");
		request.setParameter("logout_token", "logout_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verifyNoInteractions(registry, strategy, chain);
		assertThat(response.getStatus()).isEqualTo(400);
		assertThat(response.getErrorMessage()).contains("bad");
	}

}
