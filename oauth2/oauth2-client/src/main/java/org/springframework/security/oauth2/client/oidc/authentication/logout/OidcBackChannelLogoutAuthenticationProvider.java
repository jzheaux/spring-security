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

package org.springframework.security.oauth2.client.oidc.authentication.logout;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An {@link AuthenticationProvider} that authenticates an OIDC Logout Token; namely
 * deserializing it, verifying its signature, and validating its claims.
 *
 * <p>
 * Intended to be included in a
 * {@link org.springframework.security.authentication.ProviderManager}
 *
 * @author Josh Cummings
 * @since 6.2
 * @see OidcLogoutAuthenticationToken
 * @see org.springframework.security.authentication.ProviderManager
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel
 * Logout</a>
 */
public final class OidcBackChannelLogoutAuthenticationProvider implements AuthenticationProvider {

	private final Log logger = LogFactory.getLog(getClass());

	private JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory;

	private OidcSessionRegistry sessionRegistry = new InMemoryOidcSessionRegistry();

	private RestOperations restOperations = new RestTemplate();

	private String logoutEndpointName = "/logout";

	private String sessionCookieName = "JSESSIONID";

	/**
	 * Construct an {@link OidcBackChannelLogoutAuthenticationProvider}
	 */
	public OidcBackChannelLogoutAuthenticationProvider() {
		OidcIdTokenDecoderFactory logoutTokenDecoderFactory = new OidcIdTokenDecoderFactory();
		logoutTokenDecoderFactory.setJwtValidatorFactory(new DefaultOidcLogoutTokenValidatorFactory());
		this.logoutTokenDecoderFactory = logoutTokenDecoderFactory;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof OidcLogoutAuthenticationToken token)) {
			return null;
		}
		String logoutToken = token.getLogoutToken();
		ClientRegistration registration = token.getClientRegistration();
		Jwt jwt = decode(registration, logoutToken);
		OidcLogoutToken oidcLogoutToken = OidcLogoutToken.withTokenValue(logoutToken)
				.claims((claims) -> claims.putAll(jwt.getClaims())).build();
		Collection<OidcSessionInformation> loggedOut = logout(token.getBaseUrl(), oidcLogoutToken);
		return new OidcBackChannelLogoutAuthentication(oidcLogoutToken, loggedOut);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return OidcLogoutAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private Jwt decode(ClientRegistration registration, String token) {
		JwtDecoder logoutTokenDecoder = this.logoutTokenDecoderFactory.createDecoder(registration);
		try {
			return logoutTokenDecoder.decode(token);
		}
		catch (BadJwtException failed) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, failed.getMessage(),
					"https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
			throw new OAuth2AuthenticationException(error, failed);
		}
		catch (Exception failed) {
			throw new AuthenticationServiceException(failed.getMessage(), failed);
		}
	}

	private Collection<OidcSessionInformation> logout(String baseUrl, OidcLogoutToken token) {
		Iterable<OidcSessionInformation> sessions = this.sessionRegistry.removeSessionInformation(token);
		Collection<OidcSessionInformation> invalidated = new ArrayList<>();
		int totalCount = 0;
		int invalidatedCount = 0;
		for (OidcSessionInformation session : sessions) {
			totalCount++;
			try {
				eachLogout(baseUrl, session);
				invalidated.add(session);
				invalidatedCount++;
			}
			catch (RestClientException ex) {
				this.logger.debug("Failed to invalidate session", ex);
			}
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(String.format("Invalidated %d out of %d sessions", invalidatedCount, totalCount));
		}
		return invalidated;
	}

	private void eachLogout(String baseUrl, OidcSessionInformation session) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.COOKIE, this.sessionCookieName + "=" + session.getSessionId());
		for (Map.Entry<String, String> credential : session.getAuthorities().entrySet()) {
			headers.add(credential.getKey(), credential.getValue());
		}
		String logout = UriComponentsBuilder.fromHttpUrl(baseUrl).replacePath(this.logoutEndpointName).build()
				.toUriString();
		HttpEntity<?> entity = new HttpEntity<>(null, headers);
		this.restOperations.postForEntity(logout, entity, Object.class);
	}

	/**
	 * Use this {@link JwtDecoderFactory} to generate {@link JwtDecoder}s that correspond
	 * to the {@link ClientRegistration} associated with the OIDC logout token.
	 * @param logoutTokenDecoderFactory the {@link JwtDecoderFactory} to use
	 */
	public void setLogoutTokenDecoderFactory(JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory) {
		Assert.notNull(logoutTokenDecoderFactory, "logoutTokenDecoderFactory cannot be null");
		this.logoutTokenDecoderFactory = logoutTokenDecoderFactory;
	}

	public void setSessionRegistry(OidcSessionRegistry sessionRegistry) {
		this.sessionRegistry = sessionRegistry;
	}

}
