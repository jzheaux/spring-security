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

package org.springframework.security.oauth2.client.oidc.web.authentication.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.authentication.session.InMemoryOidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.oidc.authentication.session.OidcProviderSessionRegistration;
import org.springframework.security.oauth2.client.oidc.authentication.session.OidcProviderSessionRegistry;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;

/**
 * A {@link SessionAuthenticationStrategy} that links the OIDC Provider Session to the
 * Client session
 *
 * @author Josh Cummings
 * @since 6.1
 */
public final class OidcProviderSessionAuthenticationStrategy implements SessionAuthenticationStrategy {
	private final Log logger = LogFactory.getLog(getClass());

	private OidcProviderSessionRegistry providerSessionRegistry = new InMemoryOidcProviderSessionRegistry();

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return;
		}
		if (authentication == null) {
			return;
		}
		if (!(authentication.getPrincipal() instanceof OidcUser user)) {
			return;
		}
		String sessionId = session.getId();
		CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		OidcProviderSessionRegistration registration = new OidcProviderSessionRegistration(sessionId, csrfToken, user);
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(String.format("Linking a provider [%s] session to this client's session", user.getIssuer()));
		}
		this.providerSessionRegistry.register(registration);
	}

	/**
	 * The registration for linking OIDC Provider Session information to the Client's
	 * session. Defaults to in-memory.
	 * @param providerSessionRegistry the {@link OidcProviderSessionRegistry} to use
	 */
	public void setProviderSessionRegistry(OidcProviderSessionRegistry providerSessionRegistry) {
		Assert.notNull(providerSessionRegistry, "providerSessionRegistry cannot be null");
		this.providerSessionRegistry = providerSessionRegistry;
	}

}
