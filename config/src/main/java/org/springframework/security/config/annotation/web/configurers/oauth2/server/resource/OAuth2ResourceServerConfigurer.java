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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.resource;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

public final class OAuth2ResourceServerConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<OAuth2ResourceServerConfigurer<H>, H> {

	private BearerTokenResolver resolver = new DefaultBearerTokenResolver();
	private BearerTokenRequestMatcher matcher = new BearerTokenRequestMatcher();

	private BearerTokenAuthenticationEntryPoint entryPoint = new BearerTokenAuthenticationEntryPoint();
	private BearerTokenAccessDeniedHandler deniedHandler = new BearerTokenAccessDeniedHandler();

	private JwtConfigurer jwtConfigurer;

	public JwtConfigurer jwt() {
		if ( this.jwtConfigurer == null ) {
			this.jwtConfigurer = new JwtConfigurer();
		}

		return this.jwtConfigurer;
	}

	@Override
	public void setBuilder(H http) {
		super.setBuilder(http);
		initSessionCreationPolicy(http);
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
		this.matcher.setResolver(resolver);

		AuthenticationManager manager = http.getSharedObject(AuthenticationManager.class);

		BearerTokenAuthenticationFilter filter =
				new BearerTokenAuthenticationFilter(manager);
		filter.setBearerTokenResolver(resolver);
		filter = postProcess(filter);

		http.addFilterBefore(filter, BasicAuthenticationFilter.class);

		if ( this.jwtConfigurer != null ) {
			JwtDecoder decoder = getJwtDecoder(http);

			if ( decoder != null ) {
				decoder = postProcess(decoder);

				JwtAuthenticationProvider provider =
						new JwtAuthenticationProvider(decoder);
				provider = postProcess(provider);

				http.authenticationProvider(provider);

			} else {
				throw new BeanCreationException("Jwt is the only supported format for bearer tokens " +
						"in Spring Security and no instance of JwtDecoder could be found. Make sure to specify " +
						"a jwk set uri by doing http.oauth2().resourceServer().jwt().jwkSetUri(uri)");
			}
		}
	}

	public class JwtConfigurer {
		private String jwkSetUri;

		JwtConfigurer() {}

		public OAuth2ResourceServerConfigurer<H> jwkSetUri(String uri) {
			this.jwkSetUri = uri;
			return OAuth2ResourceServerConfigurer.this;
		}
	}

	private void initSessionCreationPolicy(H http) {
		if ( http.getSharedObject(SessionCreationPolicy.class) == null ) {
			http.setSharedObject(SessionCreationPolicy.class, SessionCreationPolicy.STATELESS);
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
		return this.resolver;
	}

	private JwtDecoder getJwtDecoder(H http) {
		if ( this.jwtConfigurer != null &&
				this.jwtConfigurer.jwkSetUri != null ) {
			return new NimbusJwtDecoderJwkSupport(this.jwtConfigurer.jwkSetUri);
		}

		return null;
	}

	private static class BearerTokenRequestMatcher implements RequestMatcher {
		private BearerTokenResolver resolver = new DefaultBearerTokenResolver();

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.resolver.resolve(request) != null;
		}

		public void setResolver(BearerTokenResolver resolver) {
			Assert.notNull(resolver, "resolver cannot be null");
			this.resolver = resolver;
		}
	}
}
