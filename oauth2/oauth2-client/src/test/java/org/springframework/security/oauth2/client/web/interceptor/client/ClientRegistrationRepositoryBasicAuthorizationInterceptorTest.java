/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.client.web.interceptor.client;

import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class ClientRegistrationRepositoryBasicAuthorizationInterceptorTest {
	private ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
	private String registrationId = clientRegistration.getRegistrationId();
	private ClientRegistrationRepository clientRegistrationRepository =
			new InMemoryClientRegistrationRepository(clientRegistration);

	@Test
	public void interceptWhenAuthorizationHeaderPresentThenSkips() throws Exception {
		ClientRegistrationRepositoryBasicAuthorizationInterceptor interceptor =
				new ClientRegistrationRepositoryBasicAuthorizationInterceptor(
						this.clientRegistrationRepository, this.registrationId);
		MockClientHttpRequest request = new MockClientHttpRequest();
		request.getHeaders().set(HttpHeaders.AUTHORIZATION, "authz");
		ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);

		interceptor.intercept(request, new byte[0], execution);
		assertThat(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
				.isEqualTo("authz");
		verify(execution).execute(any(), any());
	}

	@Test
	public void interceptWhenRegistrationMismatchesThenError() {
		ClientRegistrationRepository clientRegistrationRepository =
				mock(ClientRegistrationRepository.class);
		ClientRegistrationRepositoryBasicAuthorizationInterceptor interceptor =
				new ClientRegistrationRepositoryBasicAuthorizationInterceptor(
						clientRegistrationRepository, this.registrationId);
		MockClientHttpRequest request = new MockClientHttpRequest();
		ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);

		assertThatCode(() -> interceptor.intercept(request, new byte[0], execution))
			.isInstanceOf(IllegalStateException.class);
		verifyNoMoreInteractions(execution);
	}

	@Test
	public void interceptWhenRegistrationMatchesThenAuthorizationAdded() throws Exception {
		ClientRegistrationRepositoryBasicAuthorizationInterceptor interceptor =
				new ClientRegistrationRepositoryBasicAuthorizationInterceptor(
						this.clientRegistrationRepository, this.registrationId);
		MockClientHttpRequest request = new MockClientHttpRequest();
		ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);

		interceptor.intercept(request, new byte[0], execution);
		assertThat(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
				.isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		verify(execution).execute(any(), any());
	}
}
