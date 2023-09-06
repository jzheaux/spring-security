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

package org.springframework.security.config.web.server;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.util.Assert;
import org.springframework.validation.Errors;
import org.springframework.web.client.RestClientException;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link LogoutHandler} that locates the sessions associated with a given OIDC
 * Back-Channel Logout Token and invalidates each one.
 *
 * @author Josh Cummings
 * @since 6.2
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel Logout
 * Spec</a>
 */
final class OidcBackChannelServerLogoutHandler implements ServerLogoutHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private OidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();

	private WebClient web = WebClient.create();

	private String logoutEndpointName = "/logout";

	private String sessionCookieName = "JSESSIONID";

	private final OAuth2ErrorHttpMessageConverter errorHttpMessageConverter = new OAuth2ErrorHttpMessageConverter();

	@Override
	public Mono<Void> logout(WebFilterExchange exchange, Authentication authentication) {
		if (!(authentication instanceof OidcBackChannelLogoutAuthentication token)) {
			if (this.logger.isDebugEnabled()) {
				String message = "Did not perform OIDC Back-Channel Logout since authentication [%s] was of the wrong type";
				this.logger.debug(String.format(message, authentication.getClass().getSimpleName()));
			}
			return Mono.empty();
		}
		AtomicInteger totalCount = new AtomicInteger(0);
		AtomicInteger invalidatedCount = new AtomicInteger(0);
		Collection<String> errors = new CopyOnWriteArrayList<>();
		Flux<OidcSessionInformation> sessions = this.sessionRegistry.removeSessionInformation(token.getPrincipal());
		sessions.concatMap((session) -> {
			totalCount.incrementAndGet();
			return eachLogout(exchange, session)
					.flatMap((response) -> {
						invalidatedCount.incrementAndGet();
						return Mono.empty();
					})
					.onErrorResume((ex) -> {
						return this.sessionRegistry.saveSessionInformation(session)
								.map((ignore) -> ex.getMessage());
					});
		})
		.collectList().flatMap((list) ->
			if (!errors.isEmpty()) {

			}
		});
		Collection<String> errors = new ArrayList<>();
		int totalCount = 0;
		int invalidatedCount = 0;
		for (OidcSessionInformation session : sessions) {
			totalCount++;
			try {
				eachLogout(exchange, session);
				invalidatedCount++;
			}
			catch (RestClientException ex) {
				this.logger.debug("Failed to invalidate session", ex);
				errors.add(ex.getMessage());
				this.sessionRegistry.saveSessionInformation(session);
			}
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(String.format("Invalidated %d out of %d sessions", invalidatedCount, totalCount));
		}
		if (!errors.isEmpty()) {
			handleLogoutFailure(exchange.getExchange().getResponse(), oauth2Error(errors));
		}
	}

	private Mono<ResponseEntity<Void>> eachLogout(WebFilterExchange exchange, OidcSessionInformation session) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.COOKIE, this.sessionCookieName + "=" + session.getSessionId());
		for (Map.Entry<String, String> credential : session.getAuthorities().entrySet()) {
			headers.add(credential.getKey(), credential.getValue());
		}
		String url = exchange.getExchange().getRequest().getURI().toString();
		String logout = UriComponentsBuilder.fromHttpUrl(url).replacePath(this.logoutEndpointName).build()
				.toUriString();
		return this.web.post().uri(logout)
				.headers((h) -> h.putAll(headers))
				.retrieve().toBodilessEntity()
				.onErrorMap((ex) -> new SessionInvalidationException(ex, session));
	}

	private static class Errors {
		private Map<String, OidcSessionInformation> infos;

	}
	private static class SessionInvalidationException extends RuntimeException {
		private final OidcSessionInformation session;

		public SessionInvalidationException(Throwable cause, OidcSessionInformation session) {
			super(cause);
			this.session = session;
		}
	}

	private OAuth2Error oauth2Error(Collection<String> errors) {
		return new OAuth2Error("partial_logout", "not all sessions were terminated: " + errors,
				"https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
	}

	private void handleLogoutFailure(ServerHttpResponse response, OAuth2Error error) {
		response.setRawStatusCode(HttpServletResponse.SC_BAD_REQUEST);
		try {
			this.errorHttpMessageConverter.write(error, null, response);
		}
		catch (IOException ex) {
			throw new IllegalStateException(ex);
		}
	}

	/**
	 * Use this {@link OidcSessionRegistry} to identify sessions to invalidate. Note that
	 * this class uses
	 * {@link OidcSessionRegistry#removeSessionInformation(OidcLogoutToken)} to identify
	 * sessions.
	 * @param sessionRegistry the {@link OidcSessionRegistry} to use
	 */
	void setSessionRegistry(OidcSessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

	/**
	 * Use this {@link WebClient} to perform the per-session back-channel logout
	 * @param web the {@link WebClient} to use
	 */
	void setWebClient(WebClient web) {
		Assert.notNull(web, "web cannot be null");
		this.web = web;
	}

	/**
	 * Use this logout URI for performing per-session logout. Defaults to {@code /logout}
	 * since that is the default URI for
	 * {@link org.springframework.security.web.authentication.logout.LogoutFilter}.
	 * @param logoutUri the URI to use
	 */
	void setLogoutUri(String logoutUri) {
		Assert.hasText(logoutUri, "logoutUri cannot be empty");
		this.logoutEndpointName = logoutUri;
	}

	/**
	 * Use this cookie name for the session identifier. Defaults to {@code JSESSIONID}.
	 *
	 * <p>
	 * Note that if you are using Spring Session, this likely needs to change to SESSION.
	 * @param sessionCookieName the cookie name to use
	 */
	void setSessionCookieName(String sessionCookieName) {
		Assert.hasText(sessionCookieName, "clientSessionCookieName cannot be empty");
		this.sessionCookieName = sessionCookieName;
	}

}
