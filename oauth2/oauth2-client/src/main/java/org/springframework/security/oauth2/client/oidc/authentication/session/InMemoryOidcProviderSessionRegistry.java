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
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimNames;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;

/**
 * An in-memory implementation of {@link OidcProviderSessionRegistry}
 *
 * @author Josh Cummings
 * @since 6.1
 */
public final class InMemoryOidcProviderSessionRegistry implements OidcProviderSessionRegistry {

	private final Map<String, OidcProviderSessionRegistrationDetails> sessions = new ConcurrentHashMap<>();

	@Override
	public void register(OidcProviderSessionRegistrationDetails registration) {
		this.sessions.put(registration.getClientSessionId(), registration);
	}

	@Override
	public OidcProviderSessionRegistrationDetails deregister(String clientSessionId) {
		return this.sessions.remove(clientSessionId);
	}

	@Override
	public Set<OidcProviderSessionRegistrationDetails> deregister(OidcLogoutToken token) {
		String issuer = token.getIssuer().toString();
		String subject = token.getSubject();
		String providerSessionId = token.getSessionId();
		Predicate<OidcProviderSessionRegistrationDetails> matcher = (providerSessionId != null)
				? sessionIdMatcher(issuer, providerSessionId) : subjectMatcher(issuer, subject);
		Set<OidcProviderSessionRegistrationDetails> infos = new HashSet<>();
		this.sessions.values().removeIf((info) -> {
			boolean result = matcher.test(info);
			if (result) {
				infos.add(info);
			}
			return result;
		});
		return infos;
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
