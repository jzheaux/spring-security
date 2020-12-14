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

import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseDecoder;
import org.springframework.security.web.AuthenticationEntryPoint;

// receiving SLO response means logout is done, redirect to entry point
public class Saml2LogoutResponseFilter {
	private final Saml2LogoutResponseDecoder logoutResponseVerifier;
	private final AuthenticationEntryPoint entryPoint;

	// verify logout response, do any cleanup
	// redirect to entry point

	public Saml2LogoutResponseFilter(Saml2LogoutResponseDecoder logoutResponseVerifier, AuthenticationEntryPoint entryPoint) {
		this.logoutResponseVerifier = logoutResponseVerifier;
		this.entryPoint = entryPoint;
	}
}
