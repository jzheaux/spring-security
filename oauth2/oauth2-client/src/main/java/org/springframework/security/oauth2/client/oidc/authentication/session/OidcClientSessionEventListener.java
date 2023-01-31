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

import org.springframework.context.ApplicationListener;
import org.springframework.security.core.session.AbstractSessionEvent;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.session.SessionIdChangedEvent;
import org.springframework.util.Assert;

/**
 * An {@link ApplicationListener} that listens to when sessions are destroyed or session
 * ids change and updates the {@link OidcProviderSessionRegistry} accordingly.
 *
 * @author Josh Cummings
 * @since 6.1
 */
public final class OidcClientSessionEventListener implements ApplicationListener<AbstractSessionEvent> {

	private OidcProviderSessionRegistry providerSessionRegistry = new InMemoryOidcProviderSessionRegistry();

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onApplicationEvent(AbstractSessionEvent event) {
		if (event instanceof SessionDestroyedEvent destroyed) {
			this.providerSessionRegistry.deregister(destroyed.getId());
			return;
		}
		if (event instanceof SessionIdChangedEvent changed) {
			this.providerSessionRegistry.reregister(changed.getOldSessionId(), changed.getNewSessionId());
		}
	}

	/**
	 * The registry where OIDC Provider sessions are linked to the Client session.
	 * Defaults to in-memory storage.
	 * @param providerSessionRegistry the {@link OidcProviderSessionRegistry} to use
	 */
	public void setProviderSessionRegistry(OidcProviderSessionRegistry providerSessionRegistry) {
		Assert.notNull(providerSessionRegistry, "providerSessionRegistry cannot be null");
		this.providerSessionRegistry = providerSessionRegistry;
	}

}
