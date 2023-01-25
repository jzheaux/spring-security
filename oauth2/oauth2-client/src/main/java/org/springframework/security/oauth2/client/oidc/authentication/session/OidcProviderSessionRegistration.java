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

package org.springframework.security.oauth2.client.oidc.authentication.session;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

public class OidcProviderSessionRegistration implements OidcProviderSessionRegistrationDetails {

	private final String clientSessionId;

	private final CsrfToken token;

	private final OidcUser user;

	public OidcProviderSessionRegistration(String clientSessionId, CsrfToken token, OidcUser user) {
		this.clientSessionId = clientSessionId;
		this.token = extract(token);
		this.user = user;
	}

	private static CsrfToken extract(CsrfToken token) {
		if (token == null) {
			return null;
		}
		return new DefaultCsrfToken(token.getHeaderName(), token.getParameterName(), token.getToken());
	}

	@Override
	public OidcProviderSessionRegistrationDetails withClientSessionId(String clientSessionId) {
		return new OidcProviderSessionRegistration(clientSessionId, this.token, this.user);
	}

	@Override
	public String getClientSessionId() {
		return this.clientSessionId;
	}

	@Override
	public CsrfToken getCsrfToken() {
		return this.token;
	}

	@Override
	public OidcUser getPrincipal() {
		return this.user;
	}

}
