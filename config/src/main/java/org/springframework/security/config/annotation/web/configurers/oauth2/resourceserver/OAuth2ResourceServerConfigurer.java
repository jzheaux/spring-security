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

package org.springframework.security.config.annotation.web.configurers.oauth2.resourceserver;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.core.OAuth2AuthoritiesPopulator;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAuthoritiesPopulator;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenRequestMatcher;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenResolver;
import org.springframework.security.oauth2.resourceserver.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.resourceserver.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.net.URL;
import java.util.Map;

public final class OAuth2ResourceServerConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<OAuth2ResourceServerConfigurer<H>, H> {

	private final BearerTokenRequestMatcher matcher = new BearerTokenRequestMatcher();

	private BearerTokenAuthenticationEntryPoint entryPoint = new BearerTokenAuthenticationEntryPoint();
	private BearerTokenAccessDeniedHandler deniedHandler = new BearerTokenAccessDeniedHandler();

	private JwtConfigurer jwtConfigurer;

	public OAuth2ResourceServerConfigurer<H> realmName(String name) {
		this.entryPoint.setDefaultRealmName(name);
		this.deniedHandler.setDefaultRealmName(name);
		return this;
	}

	public JwtConfigurer jwt() {
		if ( this.jwtConfigurer == null ) {
			this.jwtConfigurer = new JwtConfigurer();
		}

		return this.jwtConfigurer;
	}

	@Override
	public void init(H http) throws Exception {
		registerDefaultAccessDeniedHandler(http);
		registerDefaultEntryPoint(http);
		registerDefaultCsrfOverride(http);
	}

	@Override
	public void configure(H http) throws Exception {
		BearerTokenResolver resolver = getBearerTokenResolver(http);
		resolver = postProcess(resolver);
		this.matcher.setBearerTokenResolver(resolver);

		JwtDecoder decoder = getJwtDecoder(http);

		if ( decoder != null ) {
			decoder = postProcess(decoder);

			OAuth2AuthoritiesPopulator populator = postProcess(getAuthoritiesPopulator(http));

			JwtAuthenticationProvider provider =
					new JwtAuthenticationProvider(decoder);
			provider.setAuthoritiesPopulator(populator);
			provider = postProcess(provider);

			http.authenticationProvider(provider);

			AuthenticationManager manager = http.getSharedObject(AuthenticationManager.class);

			BearerTokenAuthenticationFilter filter =
					new BearerTokenAuthenticationFilter(manager);
			filter.setBearerTokenResolver(resolver);
			filter = postProcess(filter);

			http.addFilterBefore(filter, BasicAuthenticationFilter.class);
		} else {
			throw new BeanCreationException("Jwt is the only supported format for bearer tokens " +
					"in Spring Security and no instance of JwtDecoder could be found. Either specify " +
					"a signature verification strategy by doing http.oauth2().resourceServer().jwt().signature().keys() " +
					"or by exposing a JwtDecoder instance as a @Bean");
		}
	}

	public class JwtConfigurer {
		private String algorithm = JwsAlgorithms.RS256;
		private JwtDecoder decoder = null;

		private OAuth2AuthoritiesPopulator populator;

		JwtConfigurer() {}

		public SignatureVerificationConfigurer signature() {
			return new SignatureVerificationConfigurer();
		}

		public JwtConfigurer algorithm(String algorithm) {
			this.algorithm = algorithm;
			return this;
		}

		public JwtConfigurer authoritiesPopulator(OAuth2AuthoritiesPopulator populator) {
			this.populator = populator;
			return this;
		}

		public OAuth2ResourceServerConfigurer<H> and() {
			return OAuth2ResourceServerConfigurer.this;
		}
	}

	public class SignatureVerificationConfigurer {
		SignatureVerificationConfigurer() {}

		public JwtConfigurer keys(URL url) {
			JwtConfigurer configurer = OAuth2ResourceServerConfigurer.this.jwtConfigurer;

			configurer.decoder =
					new NimbusJwtDecoderJwkSupport(url.toString(), configurer.algorithm);

			return configurer;
		}
	}

	private void registerDefaultAccessDeniedHandler(H http) {
		ExceptionHandlingConfigurer<H> exceptionHandling = http
				.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}

		exceptionHandling.defaultAccessDeniedHandlerFor(
				postProcess(this.deniedHandler),
				this.matcher);
	}

	private void registerDefaultEntryPoint(H http) {
		ExceptionHandlingConfigurer<H> exceptionHandling = http
				.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}

		exceptionHandling.defaultAuthenticationEntryPointFor(
				postProcess(this.entryPoint),
				this.matcher);
	}

	private void registerDefaultCsrfOverride(H http) {
		CsrfConfigurer<H> csrf = http
				.getConfigurer(CsrfConfigurer.class);
		if (csrf == null) {
			return;
		}

		csrf.ignoringRequestMatchers(this.matcher);
	}

	private BearerTokenResolver getBearerTokenResolver(H http) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		Map<String, BearerTokenResolver> resolvers =
				BeanFactoryUtils.beansOfTypeIncludingAncestors(context, BearerTokenResolver.class);

		if ( !resolvers.isEmpty() ) {
			return resolvers.values().iterator().next();
		}

		return new DefaultBearerTokenResolver();
	}

	private JwtDecoder getJwtDecoder(H http) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		if ( this.jwtConfigurer != null &&
				this.jwtConfigurer.decoder != null ) {
			return this.jwtConfigurer.decoder;
		}

		Map<String, JwtDecoder> decoders =
				BeanFactoryUtils.beansOfTypeIncludingAncestors(context, JwtDecoder.class);

		if ( !decoders.isEmpty() ) {
			return decoders.values().iterator().next();
		}

		return null;
	}

	private OAuth2AuthoritiesPopulator getAuthoritiesPopulator(H http) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		if ( this.jwtConfigurer != null &&
				this.jwtConfigurer.populator != null ) {
			return this.jwtConfigurer.populator;
		}

		Map<String, OAuth2AuthoritiesPopulator> populators =
				BeanFactoryUtils.beansOfTypeIncludingAncestors(context, OAuth2AuthoritiesPopulator.class);

		if ( !populators.isEmpty() ) {
			return populators.values().iterator().next();
		}

		return new JwtAuthoritiesPopulator();
	}
}
