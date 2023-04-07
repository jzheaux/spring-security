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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationListener;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.session.SessionIdChangedEvent;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimAccessor;
import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimNames;

public class InMemoryOidcProviderSessionRegistryImpl
		implements SessionRegistry, ApplicationListener<AbstractSessionEvent> {

	private final Log logger = LogFactory.getLog(InMemoryOidcProviderSessionRegistry.class);

	private final Map<String, SessionInformation> sessions = new HashMap<>();

	@Override
	public List<Object> getAllPrincipals() {
		throw new UnsupportedOperationException("unsupported");
	}

	@Override
	public List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {
		throw new UnsupportedOperationException("unsupported");
	}

	@Override
	public SessionInformation getSessionInformation(String sessionId) {
		throw new UnsupportedOperationException("unsupported");
	}

	@Override
	public void refreshLastRequest(String sessionId) {
		throw new UnsupportedOperationException("unsupported");
	}

	@Override
	public void registerNewSession(String sessionId, Object principal) {
		throw new UnsupportedOperationException("unsupported");
	}

	@Override
	public void registerNewSession(SessionInformation information) {
		this.sessions.put(information.getSessionId(), information);
	}

	@Override
	public void removeSessionInformation(String sessionId) {
		throw new UnsupportedOperationException("unsupported");
	}

	@Override
	public Iterator<SessionInformation> removeSessionInformation(Object principal) {
		if (!(principal instanceof LogoutTokenClaimAccessor token)) {
			throw new UnsupportedOperationException("unsupported");
		}
		String issuer = token.getIssuer().toString();
		String subject = token.getSubject();
		String providerSessionId = token.getSessionId();
		Predicate<SessionInformation> matcher = (providerSessionId != null)
				? sessionIdMatcher(issuer, providerSessionId) : subjectMatcher(issuer, subject);
		if (this.logger.isTraceEnabled()) {
			String message = "Looking up sessions by issuer [%s] and %s [%s]";
			if (providerSessionId != null) {
				this.logger.trace(String.format(message, issuer, LogoutTokenClaimNames.SID, providerSessionId));
			}
			else {
				this.logger.trace(String.format(message, issuer, LogoutTokenClaimNames.SUB, subject));
			}
		}
		int size = this.sessions.size();
		Set<SessionInformation> infos = new HashSet<>();
		this.sessions.values().removeIf((info) -> {
			boolean result = matcher.test(info);
			if (result) {
				infos.add(info);
			}
			return result;
		});
		if (infos.isEmpty()) {
			this.logger.debug("Failed to remove any sessions since none matched");
		}
		else if (this.logger.isTraceEnabled()) {
			String message = "Found and removed %d session(s) from mapping of %d session(s)";
			this.logger.trace(String.format(message, infos.size(), size));
		}
		return infos.iterator();
	}

	private static Predicate<SessionInformation> sessionIdMatcher(String issuer, String sessionId) {
		return (session) -> {
			String thatIssuer = ((LogoutTokenClaimAccessor) session.getPrincipal()).getIssuer().toString();
			String thatSessionId = ((LogoutTokenClaimAccessor) session.getPrincipal()).getSessionId();
			return issuer.equals(thatIssuer) && sessionId.equals(thatSessionId);
		};
	}

	private static Predicate<SessionInformation> subjectMatcher(String issuer, String subject) {
		return (session) -> {
			String thatIssuer = ((LogoutTokenClaimAccessor) session.getPrincipal()).getIssuer().toString();
			String thatSubject = ((LogoutTokenClaimAccessor) session.getPrincipal()).getSubject();
			return issuer.equals(thatIssuer) && subject.equals(thatSubject);
		};
	}

	@Override
	public void onApplicationEvent(AbstractSessionEvent event) {
		if (event instanceof SessionDestroyedEvent destroyed) {
			this.logger.debug("Received SessionDestroyedEvent");
			this.sessions.remove(destroyed.getId());
			return;
		}
		if (event instanceof SessionIdChangedEvent changed) {
			this.logger.debug("Received SessionIdChangedEvent");
			SessionInformation old = this.sessions.remove(changed.getOldSessionId());
			if (old == null) {
				this.logger.debug("Failed to register new session id since old session id was not found in registry");
				return;
			}
			SessionInformation info = new SessionInformation(old.getPrincipal(), changed.getNewSessionId(), old.getAttributes());
			this.sessions.put(info.getSessionId(), info);
		}
	}

}
