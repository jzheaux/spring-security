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

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Predicate;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimNames;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

public final class InMemoryOidcProviderSessionRegistry implements OidcProviderSessionRegistry {

	private final Set<OidcSessionInformation> sessions = new CopyOnWriteArraySet<>();

	@Override
	public SessionInformation register(HttpServletRequest request, OidcUser user) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			throw new IllegalArgumentException("cannot register OP session since client session is null");
		}
		String clientSessionId = session.getId();
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		OidcSessionInformation info = new OidcSessionInformation(user, clientSessionId, token);
		this.sessions.add(info);
		return info;
	}

	@Override
	public Set<SessionInformation> unregister(OidcLogoutToken token) {
		String issuer = token.getIssuer().toString();
		String subject = token.getSubject();
		String providerSessionId = token.getSessionId();
		Predicate<OidcSessionInformation> matcher = (providerSessionId != null)
				? sessionIdMatcher(issuer, providerSessionId) : subjectMatcher(issuer, subject);
		Set<SessionInformation> infos = new HashSet<>();
		this.sessions.removeIf((info) -> {
			boolean result = matcher.test(info);
			if (result) {
				infos.add(info);
			}
			return result;
		});
		return infos;
	}

	private static Predicate<OidcSessionInformation> sessionIdMatcher(String issuer, String sessionId) {
		return (session) -> issuer.equals(session.issuer) && sessionId.equals(session.providerSessionId);
	}

	private static Predicate<OidcSessionInformation> subjectMatcher(String issuer, String subject) {
		return (session) -> issuer.equals(session.issuer) && subject.equals(session.subject);
	}

	private static final class OidcSessionInformation extends SessionInformation {

		private final String issuer;

		private final String subject;

		private final String providerSessionId;

		private OidcSessionInformation(OidcUser user, String clientSessionId, CsrfToken token) {
			super(user, clientSessionId, Date.from(Instant.now()),
					Collections.singletonMap(CsrfToken.class.getName(), extract(token)));
			this.issuer = user.getIssuer().toString();
			this.subject = user.getSubject();
			this.providerSessionId = user.getClaimAsString(LogoutTokenClaimNames.SID);
		}

		private static CsrfToken extract(CsrfToken token) {
			if (token == null) {
				return null;
			}
			return new DefaultCsrfToken(token.getHeaderName(), token.getParameterName(), token.getToken());
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) {
				return true;
			}
			if (o == null || getClass() != o.getClass()) {
				return false;
			}
			OidcSessionInformation that = (OidcSessionInformation) o;
			return getSessionId().equals(that.getSessionId());
		}

		@Override
		public int hashCode() {
			return Objects.hash(getSessionId());
		}

	}

}
