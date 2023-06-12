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
import java.util.UUID;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimAccessor;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

public final class OidcClientSessionInformation extends SessionInformation {

	private final String issuer;

	private final String clientSessionId;

	private final CsrfToken csrfToken;

	private OidcClientSessionInformation(String name, String providerSessionId, String issuer, String clientSessionId,
			CsrfToken csrfToken) {
		super(name, providerSessionId, new Date());
		this.issuer = issuer;
		this.clientSessionId = clientSessionId;
		this.csrfToken = csrfToken;
	}

	public static Builder withOidcUser(OidcUser principal) {
		return new Builder(principal);
	}

	@Override
	public String getPrincipal() {
		return (String) super.getPrincipal();
	}

	public String getIssuer() {
		return this.issuer;
	}

	public String getClientSessionId() {
		return this.clientSessionId;
	}

	public CsrfToken getCsrfToken() {
		return this.csrfToken;
	}

	public static final class Builder {

		private final String name;

		private final String issuer;

		private String providerSessionId;

		private String clientSessionId;

		private CsrfToken csrfToken;

		private Builder(OidcUser user) {
			this.name = user.getName();
			LogoutTokenClaimAccessor claims = user::getClaims;
			if (claims.getSessionId() == null) {
				this.providerSessionId = claims.getSessionId();
			}
			this.issuer = claims.getIssuer().toExternalForm();
		}

		public Builder providerSessionId(String providerSessionId) {
			this.providerSessionId = providerSessionId;
			return this;
		}

		public Builder clientSessionId(String clientSessionId) {
			this.clientSessionId = clientSessionId;
			return this;
		}

		public Builder csrfToken(CsrfToken csrfToken) {
			this.csrfToken = new DefaultCsrfToken(csrfToken.getHeaderName(), csrfToken.getParameterName(),
					csrfToken.getToken());
			return this;
		}

		public OidcClientSessionInformation build() {
			if (this.providerSessionId == null) {
				this.providerSessionId = UUID.randomUUID().toString();
			}
			return new OidcClientSessionInformation(this.name, this.providerSessionId, this.issuer,
					this.clientSessionId, this.csrfToken);
		}

	}

}
