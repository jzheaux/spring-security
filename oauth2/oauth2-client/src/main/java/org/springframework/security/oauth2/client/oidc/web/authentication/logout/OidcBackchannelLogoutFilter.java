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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.session.InMemoryOidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.oidc.authentication.session.OidcProviderSessionRegistrationDetails;
import org.springframework.security.oauth2.client.oidc.authentication.session.OidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.authentication.logout.BackchannelLogoutAuthentication;
import org.springframework.security.web.authentication.logout.BackchannelLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A filter for the Client-side OIDC Backchannel Logout endpoint
 *
 * @author Josh Cummings
 * @since 6.1
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Backchannel Logout
 * Spec</a>
 */
public class OidcBackchannelLogoutFilter extends OncePerRequestFilter {

	private final Log logger = LogFactory.getLog(getClass());

	private static final String ERROR_MESSAGE = "{ \"error\" : \"%s\", \"error_description\" : \"%s\" }";

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory;

	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/oauth2/{registrationId}/logout", "POST");

	private OidcProviderSessionRegistry providerSessionRegistry = new InMemoryOidcProviderSessionRegistry();

	private LogoutHandler logoutHandler = new BackchannelLogoutHandler();

	/**
	 * Construct an {@link OidcBackchannelLogoutFilter}
	 * @param clients the {@link ClientRegistrationRepository} for deriving Logout Token
	 * validation
	 * @param logoutTokenDecoderFactory the {@link JwtDecoderFactory} for constructing
	 * Logout Token validators
	 */
	public OidcBackchannelLogoutFilter(ClientRegistrationRepository clients,
			JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory) {
		this.clientRegistrationRepository = clients;
		this.logoutTokenDecoderFactory = logoutTokenDecoderFactory;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
		if (!result.isMatch()) {
			chain.doFilter(request, response);
			return;
		}
		String logoutToken = request.getParameter("logout_token");
		if (logoutToken == null) {
			this.logger.debug("Did not process OIDC Backchannel Logout since no logout token was found");
			chain.doFilter(request, response);
			return;
		}
		String registrationId = result.getVariables().get("registrationId");
		ClientRegistration registration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (registration == null) {
			this.logger.debug("Did not process OIDC Backchannel Logout since no ClientRegistration was found");
			chain.doFilter(request, response);
			return;
		}
		OidcLogoutToken token;
		try {
			token = token(logoutToken, registration);
		} catch (BadJwtException ex) {
			this.logger.debug("Failed to process OIDC Backchannel Logout", ex);
			String message = String.format(ERROR_MESSAGE, "invalid_request", ex.getMessage());
			response.sendError(400, message);
			return;
		}
		int sessionCount = 0;
		int loggedOutCount = 0;
		List<String> messages = new ArrayList<>();
		Iterator<OidcProviderSessionRegistrationDetails> sessions = this.providerSessionRegistry.deregister(token);
		if (!sessions.hasNext()) {
			return;
		}
		while (sessions.hasNext()) {
			OidcProviderSessionRegistrationDetails session = sessions.next();
			BackchannelLogoutAuthentication authentication = new BackchannelLogoutAuthentication(
					session.getClientSessionId(), session.getCsrfToken());
			try {
				if (this.logger.isTraceEnabled()) {
					String message = "Logging out session #%d from result set for issuer [%s]";
					this.logger.trace(String.format(message, sessionCount, token.getIssuer()));
				}
				this.logoutHandler.logout(request, response, authentication);
				loggedOutCount++;
			} catch (Exception ex) {
				if (this.logger.isDebugEnabled()) {
					String message = "Failed to invalidate session #%d from result set for issuer [%s]";
					this.logger.debug(String.format(message, sessionCount, token.getIssuer()), ex);
				}
				messages.add(ex.getMessage());
			}
			sessionCount++;
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(String.format("Invalidated %d/%d linked sessions for issuer [%s]", loggedOutCount, sessionCount, token.getIssuer()));
		}
		if (messages.size() == sessionCount) {
			this.logger.trace("Returning a 400 since all linked sessions for issuer [%s] failed termination");
			String message = String.format(ERROR_MESSAGE, "logout_failed", messages.iterator().next(), token.getIssuer());
			response.sendError(400, message);
			return;
		}
		if (messages.size() < sessionCount) {
			this.logger.trace("Returning a 400 since not all linked sessions for issuer [%s] were successfully terminated");
			String message = String.format(ERROR_MESSAGE, "incomplete_logout", messages.iterator().next(), token.getIssuer());
			response.sendError(400, message);
		}
	}

	private OidcLogoutToken token(String logoutToken, ClientRegistration registration) {
		JwtDecoder logoutTokenDecoder = this.logoutTokenDecoderFactory.createDecoder(registration);
		OidcLogoutToken token = OidcLogoutToken.withTokenValue(logoutToken)
				.claims((claims) -> claims.putAll(logoutTokenDecoder.decode(logoutToken).getClaims())).build();
		return token;
	}

	/**
	 * The logout endpoint. Defaults to {@code /oauth2/{registrationId}/logout}.
	 * @param requestMatcher the {@link RequestMatcher} to use
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	/**
	 * The registry for linking Client sessions to OIDC Provider sessions and End Users
	 * @param providerSessionRegistry the {@link OidcProviderSessionRegistry} to use
	 */
	public void setProviderSessionRegistry(OidcProviderSessionRegistry providerSessionRegistry) {
		Assert.notNull(providerSessionRegistry, "providerSessionRegistry cannot be null");
		this.providerSessionRegistry = providerSessionRegistry;
	}

	/**
	 * The strategy for expiring each Client session indicated by the logout request.
	 * Defaults to {@link BackchannelLogoutHandler}.
	 * @param logoutHandler the {@link LogoutHandler} to use
	 */
	public void setLogoutHandler(LogoutHandler logoutHandler) {
		Assert.notNull(logoutHandler, "logoutHandler cannot be null");
		this.logoutHandler = logoutHandler;
	}

}
