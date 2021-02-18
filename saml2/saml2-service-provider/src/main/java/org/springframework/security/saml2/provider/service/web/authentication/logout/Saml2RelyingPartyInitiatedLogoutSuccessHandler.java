/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

// generate LogoutRequest and send to Asserting Party
public class Saml2RelyingPartyInitiatedLogoutSuccessHandler implements LogoutSuccessHandler {
	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;
	private final Saml2LogoutRequestResolver logoutRequestResolver;
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public Saml2RelyingPartyInitiatedLogoutSuccessHandler(Saml2LogoutRequestResolver logoutRequestResolver) {
		this.logoutRequestResolver = logoutRequestResolver;
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		RelyingPartyRegistration registration;
		if (authentication instanceof Saml2Authentication) {
			registration = this.relyingPartyRegistrationResolver.resolve(request, ((Saml2Authentication) authentication).getAuthorizedRelyingPartyRegistrationId()));
		} else {
			registration = this.relyingPartyRegistrationResolver.resolve(request);
		}
		// generate logout request
		Saml2LogoutRequest logoutRequest = this.logoutRequestResolver.resolveLogoutR
		Saml2MessageBinding binding = registration.getAssertingPartyDetails().getSingleLogoutServiceBinding();
		if (binding == Saml2MessageBinding.REDIRECT) {
			String location = registration.getAssertingPartyDetails().getSingleLogoutServiceLocation();
			UriComponentsBuilder uriBuilder = UriComponentsBuilder
					.fromUriString(authenticationRequest.getAuthenticationRequestUri());
			addParameter("SAMLRequest", authenticationRequest.getSamlRequest(), uriBuilder);
			addParameter("SigAlg", authenticationRequest.getSigAlg(), uriBuilder);
			addParameter("Signature", authenticationRequest.getSignature(), uriBuilder);
			String redirectUrl = uriBuilder.build(true).toUriString();
			this.redirectStrategy.sendRedirect(request, response, redirectUrl);
		}
		// redirect to asserting party
	}
}
