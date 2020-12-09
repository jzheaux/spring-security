/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication;

import java.time.Clock;
import java.time.Instant;
import java.util.function.Consumer;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.saml.saml2.core.AuthnRequest;

import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.util.Assert;

/**
 * A strategy for resolving a SAML 2.0 Authentication Request from the
 * {@link HttpServletRequest} using OpenSAML.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class OpenSaml4AuthenticationRequestResolver implements Saml2AuthenticationRequestResolver {

	private final OpenSamlAuthenticationRequestResolver authnRequestResolver;

	private Consumer<AuthenticationRequestParameters> parametersConsumer = (parameters) -> {
	};

	private Clock clock = Clock.systemUTC();

	/**
	 * Construct a {@link OpenSaml4AuthenticationRequestResolver}
	 */
	public OpenSaml4AuthenticationRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.authnRequestResolver = new OpenSamlAuthenticationRequestResolver(relyingPartyRegistrationResolver);
	}

	@Override
	public <T extends AbstractSaml2AuthenticationRequest> T resolve(HttpServletRequest request, String registrationId) {
		return this.authnRequestResolver.resolve(request, registrationId, (registration, authnRequest) -> {
			authnRequest.setIssueInstant(Instant.now(this.clock));
			this.parametersConsumer.accept(new AuthenticationRequestParameters(request, registration, authnRequest));
		});
	}

	/**
	 * Set a {@link Consumer} for modifying the OpenSAML {@link AuthnRequest}
	 * @param parametersConsumer a consumer that accepts an
	 * {@link AuthenticationRequestParameters}
	 */
	public void setParametersConsumer(Consumer<AuthenticationRequestParameters> parametersConsumer) {
		Assert.notNull(parametersConsumer, "parametersConsumer cannot be null");
		this.parametersConsumer = parametersConsumer;
	}

	/**
	 * Use this {@link Clock} for generating the issued {@link Instant}
	 * @param clock the {@link Clock} to use
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock must not be null");
		this.clock = clock;
	}

	public static final class AuthenticationRequestParameters {

		private final HttpServletRequest request;

		private final RelyingPartyRegistration registration;

		private final AuthnRequest authnRequest;

		public AuthenticationRequestParameters(HttpServletRequest request, RelyingPartyRegistration registration,
				AuthnRequest authnRequest) {
			this.request = request;
			this.registration = registration;
			this.authnRequest = authnRequest;
		}

		public HttpServletRequest getRequest() {
			return this.request;
		}

		public RelyingPartyRegistration getRelyingPartyRegistration() {
			return this.registration;
		}

		public AuthnRequest getAuthnRequest() {
			return this.authnRequest;
		}

	}

}
