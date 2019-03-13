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

import java.io.IOException;
import java.util.Optional;
import java.util.function.BiConsumer;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.Assert;

public class ClientRegistrationRepositoryBasicAuthorizationInterceptor
		implements ClientHttpRequestInterceptor {

	private static final String ERROR = "Unable to apply client id and secret from client registration: %s";

	private final ClientRegistrationRepository clientRegistrationRepository;
	private final String registrationId;

	public ClientRegistrationRepositoryBasicAuthorizationInterceptor
			(ClientRegistrationRepository clientRegistrationRepository, String registrationId) {

		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(registrationId, "registrationId cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.registrationId = registrationId;
	}

	@Override
	public ClientHttpResponse intercept
			(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {

		maybeAddAuthorization(request.getHeaders());
		return execution.execute(request, body);
	}

	private void maybeAddAuthorization(HttpHeaders headers) {
		if (isMissingAuthorization(headers)) {
			Optional.of(headers)
					.map(this::applyAuthorization)
					.flatMap(this::fromClientRegistration)
					.orElseThrow(() -> new IllegalStateException(String.format(ERROR, this.registrationId)));
		}
	}

	private boolean isMissingAuthorization(HttpHeaders headers) {
		return !headers.containsKey(HttpHeaders.AUTHORIZATION);
	}

	private BiConsumer<String, String> applyAuthorization(HttpHeaders headers) {
		return headers::setBasicAuth;
	}

	private Optional<ClientRegistration> fromClientRegistration(BiConsumer<String, String> authorization) {
		return clientRegistration().map(clientRegistration -> {
			authorization.accept(clientRegistration.getClientId(), clientRegistration.getClientSecret());
			return clientRegistration;
		});
	}

	private Optional<ClientRegistration> clientRegistration() {
		return Optional.of(this.registrationId)
				.map(this.clientRegistrationRepository::findByRegistrationId);
	}
}
