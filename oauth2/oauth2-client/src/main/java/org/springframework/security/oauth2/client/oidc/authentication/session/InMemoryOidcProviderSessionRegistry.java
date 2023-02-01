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

import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimNames;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;

/**
 * An in-memory implementation of {@link OidcProviderSessionRegistry}
 *
 * @author Josh Cummings
 * @since 6.1
 */
public final class InMemoryOidcProviderSessionRegistry implements OidcProviderSessionRegistry {

	private final Log logger = LogFactory.getLog(InMemoryOidcProviderSessionRegistry.class);

	private final Map<String, OidcProviderSessionRegistrationDetails> sessions = new ConcurrentHashMap<>();

	@Override
	public void register(OidcProviderSessionRegistrationDetails registration) {
		this.sessions.put(registration.getClientSessionId(), registration);
	}

	@Override
	public void reregister(String oldClientSessionId, String newClientSessionId) {
		OidcProviderSessionRegistrationDetails old = this.sessions.remove(oldClientSessionId);
		if (old == null) {
			this.logger.debug("Failed to register new session id since old session id was not found in registry");
			return;
		}
		register(new OidcProviderSessionRegistration(newClientSessionId, old.getCsrfToken(), old.getPrincipal()));
	}

	@Override
	public OidcProviderSessionRegistrationDetails deregister(String clientSessionId) {
		OidcProviderSessionRegistrationDetails details = this.sessions.remove(clientSessionId);
		if (details != null) {
			this.logger.trace("Removed client session");
		}
		return details;
	}

	@Override
	public Iterator<OidcProviderSessionRegistrationDetails> deregister(OidcLogoutToken token) {
		String issuer = token.getIssuer().toString();
		String subject = token.getSubject();
		String providerSessionId = token.getSessionId();
		Predicate<OidcProviderSessionRegistrationDetails> matcher = (providerSessionId != null)
				? sessionIdMatcher(issuer, providerSessionId) : subjectMatcher(issuer, subject);
		if (this.logger.isTraceEnabled()) {
			String message = "Looking up sessions by issuer [%s] and %s [%s]";
			if (providerSessionId != null) {
				this.logger.trace(String.format(message, issuer, LogoutTokenClaimNames.SID, providerSessionId));
			} else {
				this.logger.trace(String.format(message, issuer, LogoutTokenClaimNames.SUB, subject));
			}
		}
		int size = this.sessions.size();
		Set<OidcProviderSessionRegistrationDetails> infos = new HashSet<>();
		this.sessions.values().removeIf((info) -> {
			boolean result = matcher.test(info);
			if (result) {
				infos.add(info);
			}
			return result;
		});
		if (infos.isEmpty()) {
			this.logger.debug("Failed to remove any sessions since none matched");
		} else if (this.logger.isTraceEnabled()) {
			String message = "Found and removed %d session(s) from mapping of %d session(s)";
			this.logger.trace(String.format(message, infos.size(), size));
		}
		return infos.iterator();
	}

	private static Predicate<OidcProviderSessionRegistrationDetails> sessionIdMatcher(String issuer, String sessionId) {
		return (session) -> {
			String thatIssuer = session.getPrincipal().getIssuer().toString();
			String thatSessionId = session.getPrincipal().getClaimAsString(LogoutTokenClaimNames.SID);
			return issuer.equals(thatIssuer) && sessionId.equals(thatSessionId);
		};
	}

	private static Predicate<OidcProviderSessionRegistrationDetails> subjectMatcher(String issuer, String subject) {
		return (session) -> {
			String thatIssuer = session.getPrincipal().getIssuer().toString();
			String thatSubject = session.getPrincipal().getSubject();
			return issuer.equals(thatIssuer) && subject.equals(thatSubject);
		};
	}

}
