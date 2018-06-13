/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.autoconfigure.security.oauth2.resourceserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.util.StringUtils;

import java.net.URL;
import java.util.Map;

/**
 * @author Josh Cummings
 */
@Configuration
@EnableConfigurationProperties(OAuth2ResourceServerProperties.class)
public class OAuth2ResourceServerWebSecurityConfiguraion {
	private final OAuth2ResourceServerProperties properties;

	OAuth2ResourceServerWebSecurityConfiguraion(OAuth2ResourceServerProperties properties) {
		this.properties = properties;
	}

	@Configuration
	@ConditionalOnMissingBean(WebSecurityConfigurerAdapter.class)
	static class OAuth2WebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
		@Autowired
		OAuth2ResourceServerProperties properties;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated();

			OAuth2ResourceServerProperties.IssuerDetails issuer = this.singleRealm();

			if ( issuer != null ) {
				if (StringUtils.hasText(issuer.getAlgorithm())) {
					// @formatter:on
					http
						.oauth2()
							.resourceServer()
								.jwt().algorithm(issuer.getAlgorithm());
					// @formatter:off
				}

				if (StringUtils.hasText(issuer.getJwkSetUri())) {
					// @formatter:on
					http
						.oauth2()
							.resourceServer()
								.jwt().signature().keys(new URL(issuer.getJwkSetUri()));
					// @formatter:off
				}
			}

		}

		private OAuth2ResourceServerProperties.IssuerDetails singleRealm() {
			Map<String, OAuth2ResourceServerProperties.IssuerDetails> realms = this.properties.getIssuer();
			return realms.isEmpty() ? null : realms.entrySet().iterator().next().getValue();
		}
	}
}
