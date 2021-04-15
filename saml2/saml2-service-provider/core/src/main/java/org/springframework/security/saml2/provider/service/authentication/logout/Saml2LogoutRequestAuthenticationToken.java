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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

public class Saml2LogoutRequestAuthenticationToken extends AbstractAuthenticationToken {

	private final Saml2LogoutRequest logoutRequest;

	private final RelyingPartyRegistration relyingPartyRegistration;

	private final Authentication authentication;

	public Saml2LogoutRequestAuthenticationToken(Saml2LogoutRequest logoutRequest,
			RelyingPartyRegistration registration, Authentication authentication) {
		super(Collections.emptyList());
		this.logoutRequest = logoutRequest;
		this.relyingPartyRegistration = registration;
		this.authentication = authentication;
	}

	public Saml2LogoutRequest getLogoutRequest() {
		return this.logoutRequest;
	}

	public RelyingPartyRegistration getRelyingPartyRegistration() {
		return this.relyingPartyRegistration;
	}

	public Authentication getAuthentication() {
		return this.authentication;
	}

	@Override
	public Object getCredentials() {
		return this.logoutRequest;
	}

	@Override
	public Object getPrincipal() {
		return this.logoutRequest;
	}

}
