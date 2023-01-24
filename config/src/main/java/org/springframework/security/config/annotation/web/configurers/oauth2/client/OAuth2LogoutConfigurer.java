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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.util.function.Consumer;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.oauth2.client.oidc.authentication.logout.NimbusLogoutTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.web.authentication.logout.OidcBackchannelLogoutFilter;
import org.springframework.security.oauth2.client.oidc.web.authentication.session.InMemoryOidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.oidc.web.authentication.session.OidcProviderSessionAuthenticationStrategy;
import org.springframework.security.oauth2.client.oidc.web.authentication.session.OidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.session.BackchannelSessionInformationExpiredStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.util.Assert;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Logout flows
 *
 * <p>
 * OAuth 2.0 Logout provides an application with the capability to have users log out by
 * using their existing account at an OAuth 2.0 or OpenID Connect 1.0 Provider.
 *
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter} is populated:
 *
 * <ul>
 * <li>{@link OidcBackchannelLogoutFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository}</li>
 * </ul>
 *
 * @author Josh Cummings
 * @since 6.1
 * @see HttpSecurity#oauth2Logout()
 * @see OidcBackchannelLogoutFilter
 * @see ClientRegistrationRepository
 */
public final class OAuth2LogoutConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OAuth2LogoutConfigurer<B>, B> {

	private BackchannelLogoutConfigurer backchannel;

	/**
	 * Sets the repository of client registrations.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @return the {@link OAuth2LogoutConfigurer} for further configuration
	 */
	public OAuth2LogoutConfigurer<B> backchannel(Consumer<BackchannelLogoutConfigurer> backchannelLogoutConfigurer) {
		if (this.backchannel == null) {
			this.backchannel = new BackchannelLogoutConfigurer();
		}
		backchannelLogoutConfigurer.accept(this.backchannel);
		return this;
	}

	public B and() {
		return getBuilder();
	}

	@Override
	public void configure(B builder) throws Exception {
		if (this.backchannel != null) {
			this.backchannel.configure(builder);
		}
	}

	public final class BackchannelLogoutConfigurer {

		private SessionInformationExpiredStrategy expiredStrategy = new BackchannelSessionInformationExpiredStrategy();

		private JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory = new NimbusLogoutTokenDecoderFactory();

		private OidcProviderSessionRegistry providerSessionRegistry = new InMemoryOidcProviderSessionRegistry();

		public BackchannelLogoutConfigurer clientSessionExpiredStrategy(
				SessionInformationExpiredStrategy expiredStrategy) {
			Assert.notNull(expiredStrategy, "expiredStrategy cannot be null");
			this.expiredStrategy = expiredStrategy;
			return this;
		}

		public BackchannelLogoutConfigurer oidcLogoutTokenDecoderFactory(
				JwtDecoderFactory<ClientRegistration> logoutTokenDecoderFactory) {
			Assert.notNull(logoutTokenDecoderFactory, "logoutTokenDecoderFactory cannot be null");
			this.logoutTokenDecoderFactory = logoutTokenDecoderFactory;
			return this;
		}

		public BackchannelLogoutConfigurer oidcProviderSessionRegistry(
				OidcProviderSessionRegistry providerSessionRegistry) {
			Assert.notNull(providerSessionRegistry, "providerSessionRegistry cannot be null");
			this.providerSessionRegistry = providerSessionRegistry;
			return this;
		}

		private JwtDecoderFactory<ClientRegistration> oidcLogoutTokenDecoderFactory() {
			return this.logoutTokenDecoderFactory;
		}

		private OidcProviderSessionRegistry oidcProviderSessionRegistry() {
			return this.providerSessionRegistry;
		}

		private SessionInformationExpiredStrategy expiredStrategy() {
			return this.expiredStrategy;
		}

		private SessionAuthenticationStrategy sessionAuthenticationStrategy() {
			OidcProviderSessionAuthenticationStrategy strategy = new OidcProviderSessionAuthenticationStrategy();
			strategy.setProviderSessionRegistry(oidcProviderSessionRegistry());
			return strategy;
		}

		void configure(B http) {
			ClientRegistrationRepository clientRegistrationRepository = OAuth2ClientConfigurerUtils
					.getClientRegistrationRepository(http);
			OidcBackchannelLogoutFilter filter = new OidcBackchannelLogoutFilter(clientRegistrationRepository,
					oidcLogoutTokenDecoderFactory());
			filter.setProviderSessionRegistry(oidcProviderSessionRegistry());
			SessionInformationExpiredStrategy expiredStrategy = expiredStrategy();
			filter.setExpiredStrategy(expiredStrategy);
			http.addFilterBefore(filter, CsrfFilter.class);
			SessionManagementConfigurer<B> sessionConfigurer = http.getConfigurer(SessionManagementConfigurer.class);
			if (sessionConfigurer != null) {
				sessionConfigurer.addSessionAuthenticationStrategy(sessionAuthenticationStrategy());
			}
		}

	}

}
