package org.springframework.security.oauth2.client.oidc.authentication.logout;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.security.oauth2.core.oidc.OidcIdToken;

public class InMemoryOidcProviderSessionRegistry implements OidcProviderSessionRegistry {
	private Map<String, String> providerToClientSessionId = new ConcurrentHashMap<>();
	private Map<String, List<String>> clientIdToSessionIds = new ConcurrentHashMap<>();
	private Map<String, List<String>> subjectToSessionIds = new ConcurrentHashMap<>();

	@Override
	public void mapClientSession(OidcIdToken token, String clientSessionId) {
		String sid = token.getClaim("sid");
		if (sid != null) {
			this.providerToClientSessionId.put(sid, clientSessionId);
		}
		String clientId = token.getClaim("clientId");
		if (clientId != null) { // how to get the client id?
			this.clientIdToSessionIds.computeIfAbsent(clientId, (k) -> new CopyOnWriteArrayList<>()).add(clientSessionId);
		}
		String subject = token.getSubject();
		if (subject != null) {
			subjectToSessionIds.computeIfAbsent(subject, (k) -> new CopyOnWriteArrayList<>()).add(clientSessionId);
		}
	}

	@Override
	public Collection<String> getClientSessions(OidcLogoutToken token) {
		return null;
	}
}
