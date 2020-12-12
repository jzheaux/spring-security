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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestVerifier;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutHandler;


// received LogoutRequest from asserting party; process, throw exception if fail
public class Saml2LogoutRequestHandler implements LogoutHandler {
	private final Saml2LogoutRequestVerifier logoutRequestVerifier;
	private final Saml2LogoutResponseResolver logoutResponseResolver;
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public Saml2LogoutRequestHandler(Saml2LogoutRequestVerifier logoutRequestVerifier, Saml2LogoutResponseResolver logoutResponseResolver) {
		this.logoutRequestVerifier = logoutRequestVerifier;
		this.logoutResponseResolver = logoutResponseResolver;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		// verify logout request
		// generate logout response
		// redirect to asserting party
	}
}
