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
import java.util.Collection;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.client.oidc.authentication.logout.InMemoryOidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.session.BackchannelSessionInformationExpiredStrategy;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

public class OidcBackchannelLogoutFilter extends OncePerRequestFilter {

	private static final String ERROR_MESSAGE = "{ \"error\" : \"%s\", \"error_description\" : \"%s\" }";

	private final ClientRegistrationRepository clients;

	private final JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory;

	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/oauth2/{registrationId}/logout", "POST");

	private OidcProviderSessionRegistry providerSessionRegistry = new InMemoryOidcProviderSessionRegistry();

	private SessionInformationExpiredStrategy expiredStrategy = new BackchannelSessionInformationExpiredStrategy();

	public OidcBackchannelLogoutFilter(ClientRegistrationRepository clients,
			JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory) {
		this.clients = clients;
		this.logoutTokenDecoderFactory = logoutTokenDecoderFactory;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
		if (!result.isMatch()) {
			chain.doFilter(request, response);
			return;
		}
		String token = request.getParameter("logout_token");
		if (token == null) {
			chain.doFilter(request, response);
			return;
		}
		String registrationId = result.getVariables().get("registrationId");
		ClientRegistration registration = this.clients.findByRegistrationId(registrationId);
		if (registration == null) {
			chain.doFilter(request, response);
			return;
		}
		try {
			JwtDecoder logoutTokenDecoder = this.logoutTokenDecoderFactory.createDecoder(registration);
			OidcLogoutToken logoutToken = OidcLogoutToken.withTokenValue(token)
					.claims((claims) -> claims.putAll(logoutTokenDecoder.decode(token).getClaims())).build();
			Collection<SessionInformation> sessions = this.providerSessionRegistry.unregister(logoutToken);
			for (SessionInformation info : sessions) {
				SessionInformationExpiredEvent event = new SessionInformationExpiredEvent(info, request, response);
				this.expiredStrategy.onExpiredSessionDetected(event);
			}
		}
		catch (BadJwtException ex) {
			String message = String.format(ERROR_MESSAGE, "invalid_request", ex.getMessage());
			response.sendError(400, message);
		}
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	public void setProviderSessionRegistry(OidcProviderSessionRegistry providerSessionRegistry) {
		Assert.notNull(providerSessionRegistry, "providerSessionRegistry cannot be null");
		this.providerSessionRegistry = providerSessionRegistry;
	}

	public void setExpiredStrategy(SessionInformationExpiredStrategy expiredStrategy) {
		Assert.notNull(expiredStrategy, "expiredStrategy cannot be null");
		this.expiredStrategy = expiredStrategy;
	}

}
