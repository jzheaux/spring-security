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

package org.springframework.security.oauth2.client.oidc.web;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutAuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcLogoutAuthenticationConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

public class OidcBackChannelLogoutFilterTests {

	@Test
	public void doFilterRequestDoesNotMatchThenDoesNotRun() throws Exception {
		ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		OidcBackChannelLogoutFilter backChannelLogoutFilter = new OidcBackChannelLogoutFilter(
				new OidcLogoutAuthenticationConverter(clientRegistrationRepository), authenticationManager);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		backChannelLogoutFilter.doFilter(request, response, chain);
		verifyNoInteractions(clientRegistrationRepository, authenticationManager);
		verify(chain).doFilter(request, response);
	}

	@Test
	public void doFilterRequestDoesNotMatchContainLogoutTokenThenBadRequest() throws Exception {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		given(clientRegistrationRepository.findByRegistrationId(any())).willReturn(clientRegistration);
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		OidcBackChannelLogoutFilter filter = new OidcBackChannelLogoutFilter(
				new OidcLogoutAuthenticationConverter(clientRegistrationRepository), authenticationManager);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/connect/back-channel/id");
		request.setServletPath("/logout/connect/back-channel/id");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verifyNoInteractions(authenticationManager, chain);
		assertThat(response.getStatus()).isEqualTo(400);
	}

	@Test
	public void doFilterWithNoMatchingClientThenBadRequest() throws Exception {
		ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		OidcBackChannelLogoutFilter backChannelLogoutFilter = new OidcBackChannelLogoutFilter(
				new OidcLogoutAuthenticationConverter(clientRegistrationRepository), authenticationManager);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/connect/back-channel/id");
		request.setServletPath("/logout/connect/back-channel/id");
		request.setParameter("logout_token", "logout_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		backChannelLogoutFilter.doFilter(request, response, chain);
		verify(clientRegistrationRepository).findByRegistrationId("id");
		verifyNoInteractions(authenticationManager, chain);
		assertThat(response.getStatus()).isEqualTo(400);
	}

	@Test
	public void doFilterWithSessionMatchingLogoutTokenThenInvalidates() throws Exception {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		given(clientRegistrationRepository.findByRegistrationId(any())).willReturn(clientRegistration);
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		OidcBackChannelLogoutFilter filter = new OidcBackChannelLogoutFilter(
				new OidcLogoutAuthenticationConverter(clientRegistrationRepository), authenticationManager);
		MockHttpServletRequest request = new MockHttpServletRequest("POST",
				"/oauth2/" + clientRegistration.getRegistrationId() + "/logout");
		request.setServletPath("/logout/connect/back-channel/id");
		request.setParameter("logout_token", "logout_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		ArgumentCaptor<OidcLogoutAuthenticationToken> authentication = ArgumentCaptor
				.forClass(OidcLogoutAuthenticationToken.class);
		verify(authenticationManager).authenticate(authentication.capture());
		assertThat(authentication.getValue().getLogoutToken()).isEqualTo("logout_token");
		verifyNoInteractions(chain);
		assertThat(response.getStatus()).isEqualTo(200);
	}

	@Test
	public void doFilterWhenInvalidJwtThenBadRequest() throws Exception {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		given(clientRegistrationRepository.findByRegistrationId(any())).willReturn(clientRegistration);
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		given(authenticationManager.authenticate(any())).willThrow(new BadCredentialsException("bad"));
		OidcBackChannelLogoutFilter backChannelLogoutFilter = new OidcBackChannelLogoutFilter(
				new OidcLogoutAuthenticationConverter(clientRegistrationRepository), authenticationManager);
		MockHttpServletRequest request = new MockHttpServletRequest("POST",
				"/oauth2/" + clientRegistration.getRegistrationId() + "/logout");
		request.setServletPath("/logout/connect/back-channel/id");
		request.setParameter("logout_token", "logout_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		backChannelLogoutFilter.doFilter(request, response, chain);
		verifyNoInteractions(chain);
		assertThat(response.getStatus()).isEqualTo(400);
		assertThat(response.getContentAsString()).contains("bad");
	}

}
