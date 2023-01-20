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

import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.TestOidcUsers;

import static org.assertj.core.api.Assertions.assertThat;

public class InMemoryOidcProviderSessionRegistryTests {

	@Test
	public void registerWhenDefaultsThenStoresSessionInformation() {
		InMemoryOidcProviderSessionRegistry registry = new InMemoryOidcProviderSessionRegistry();
		String sessionId = "client";
		OidcUser user = TestOidcUsers.create();
		SessionInformation info = registry.register(user, sessionId);
		assertThat(info.getSessionId()).isSameAs(sessionId);
		assertThat(info.getPrincipal()).isSameAs(user);
		Set<SessionInformation> infos = registry.unregister(TestOidcLogoutTokens.withUser(user).build());
		assertThat(infos).containsExactly(info);
	}

	@Test
	public void registerWhenIdTokenHasSessionIdThenStoresSessionInformation() {
		InMemoryOidcProviderSessionRegistry registry = new InMemoryOidcProviderSessionRegistry();
		OidcIdToken token = TestOidcIdTokens.idToken().claim("sid", "provider").build();
		OidcUser user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
		SessionInformation info = registry.register(user, "client");
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.withSessionId(token.getIssuer().toString(), "provider")
				.build();
		Set<SessionInformation> infos = registry.unregister(logoutToken);
		assertThat(infos).containsExactly(info);
	}

	@Test
	public void unregisterWhenMultipleSessionsThenRemovesAllMatching() {
		InMemoryOidcProviderSessionRegistry registry = new InMemoryOidcProviderSessionRegistry();
		OidcIdToken token = TestOidcIdTokens.idToken().claim("sid", "providerOne").subject("otheruser").build();
		OidcUser user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
		SessionInformation one = registry.register(user, "clientOne");
		token = TestOidcIdTokens.idToken().claim("sid", "providerTwo").build();
		user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
		SessionInformation two = registry.register(user, "clientTwo");
		token = TestOidcIdTokens.idToken().claim("sid", "providerThree").build();
		user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
		SessionInformation three = registry.register(user, "clientThree");
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.withSubject(token.getIssuer().toString(), token.getSubject())
				.build();
		Set<SessionInformation> infos = registry.unregister(logoutToken);
		assertThat(infos).containsExactly(two, three);
		logoutToken = TestOidcLogoutTokens.withSubject(token.getIssuer().toString(), "otheruser").build();
		infos = registry.unregister(logoutToken);
		assertThat(infos).containsExactly(one);
	}

	@Test
	public void unregisterWhenNoSessionsThenEmptyList() {
		InMemoryOidcProviderSessionRegistry registry = new InMemoryOidcProviderSessionRegistry();
		OidcIdToken token = TestOidcIdTokens.idToken().claim("sid", "provider").build();
		OidcUser user = new DefaultOidcUser(AuthorityUtils.NO_AUTHORITIES, token);
		registry.register(user, "client");
		OidcLogoutToken logoutToken = TestOidcLogoutTokens.withSessionId(token.getIssuer().toString(), "wrong").build();
		Set<SessionInformation> infos = registry.unregister(logoutToken);
		assertThat(infos).isNotNull();
		assertThat(infos).isEmpty();
		logoutToken = TestOidcLogoutTokens.withSessionId("https://wrong", "provider").build();
		infos = registry.unregister(logoutToken);
		assertThat(infos).isNotNull();
		assertThat(infos).isEmpty();
	}

}
