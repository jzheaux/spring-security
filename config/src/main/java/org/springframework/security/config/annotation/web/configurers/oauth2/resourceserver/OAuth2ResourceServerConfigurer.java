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

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.oauth2.core.OAuth2AuthoritiesPopulator;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAccessTokenAuthenticationProvider;
import org.springframework.security.oauth2.resourceserver.authentication.JwtAuthoritiesPopulator;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenRequestMatcher;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenResolver;
import org.springframework.security.oauth2.resourceserver.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.resourceserver.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.util.StringUtils;

import java.net.URL;
import java.util.Arrays;
import java.util.Map;

public final class OAuth2ResourceServerConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractHttpConfigurer<OAuth2ResourceServerConfigurer<H>, H> {

	private BearerTokenResolver resolver;

	private JwtAccessTokenFormatConfigurer jwtAccessTokenFormatConfigurer;

	public OAuth2ResourceServerConfigurer<H> bearerTokenResolver(BearerTokenResolver resolver) {
		this.resolver = resolver;
		return this;
	}

	public NeedsSignatureJwtAccessTokenFormatConfigurer jwt() {
		if ( this.jwtAccessTokenFormatConfigurer == null ) {
			this.jwtAccessTokenFormatConfigurer = new NeedsSignatureJwtAccessTokenFormatConfigurer();
		}

		//TODO don't forget the ClassCastException risk inherent in this design
		return (NeedsSignatureJwtAccessTokenFormatConfigurer) this.jwtAccessTokenFormatConfigurer;
	}

	public JwtAccessTokenFormatConfigurer jwt(JwtDecoder decoder) {
		if ( this.jwtAccessTokenFormatConfigurer == null ) {
			this.jwtAccessTokenFormatConfigurer = new JwtAccessTokenFormatConfigurer(decoder);
		}


		return this.jwtAccessTokenFormatConfigurer;
	}

	@Override
	public void init(H builder) throws Exception {
		super.init(builder);
	}

	@Override
	public void configure(H http) throws Exception {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		if ( this.resolver == null ) {
			Map<String, BearerTokenResolver> resolvers =
					BeanFactoryUtils.beansOfTypeIncludingAncestors(context, BearerTokenResolver.class);

			if ( !resolvers.isEmpty() ) {
				this.resolver = resolvers.values().iterator().next();
			}
		}

		if ( this.resolver == null ) {
			this.resolver = new DefaultBearerTokenResolver();
		}

		BearerTokenRequestMatcher matcher = new BearerTokenRequestMatcher();

		exceptionHandling(http)
				.defaultAuthenticationEntryPointFor(
						new BearerTokenAuthenticationEntryPoint(),
						matcher)
				.defaultAccessDeniedHandlerFor(
						new BearerTokenAccessDeniedHandler(),
						matcher);

		http.addFilterBefore(bearerTokenAuthenticationFilter(), CsrfFilter.class);
	}

	public class JwtAccessTokenFormatConfigurer {
		protected JwtDecoderConfigurer jwtDecoder = new JwtDecoderConfigurer();
		private OAuth2AuthoritiesPopulator populator;
		private String scopeAttributeName;

		public JwtAccessTokenFormatConfigurer() {}

		public JwtAccessTokenFormatConfigurer(JwtDecoder decoder) {
			this.jwtDecoder.decoder(decoder);
		}

		public JwtAccessTokenFormatConfigurer authoritiesPopulator(OAuth2AuthoritiesPopulator populator) {
			this.populator = populator;
			return this;
		}

		public JwtAccessTokenFormatConfigurer scopeAttributeName(String scopeAttributeName) {
			this.scopeAttributeName = scopeAttributeName;
			return this;
		}

		public OAuth2ResourceServerConfigurer<H> and() {
			return OAuth2ResourceServerConfigurer.this;
		}
	}

	public class NeedsSignatureJwtAccessTokenFormatConfigurer
			extends JwtAccessTokenFormatConfigurer {

		protected String algorithm = JwsAlgorithms.RS256;

		public NeedsSignatureJwtAccessTokenFormatConfigurer algorithm(String algorithm) {
			this.algorithm = algorithm;
			return this;
		}

		public SignatureVerificationConfigurer signature() {
			return new SignatureVerificationConfigurer(this);
		}
	}

	public class SignatureVerificationConfigurer {
		private NeedsSignatureJwtAccessTokenFormatConfigurer parent;

		public SignatureVerificationConfigurer(NeedsSignatureJwtAccessTokenFormatConfigurer parent) {
			this.parent = parent;
		}

		public JwtAccessTokenFormatConfigurer keys(URL url) {
			this.parent.jwtDecoder.decoder(
					new NimbusJwtDecoderJwkSupport(url.toString(), this.parent.algorithm));

			return this.parent;
		}
	}

	public class JwtDecoderConfigurer {
		private JwtDecoder jwtDecoder;

		public JwtDecoderConfigurer decoder(JwtDecoder decoder) {
			this.jwtDecoder = decoder;
			return this;
		}

		public JwtDecoder decoder() {
			return this.jwtDecoder;
		}
	}


	private SessionManagementConfigurer<H> sessionManagement(H http) {
		return http.getConfigurer(SessionManagementConfigurer.class);
	}

	private ExceptionHandlingConfigurer<H> exceptionHandling(H http) {
		return http.getConfigurer(ExceptionHandlingConfigurer.class);
	}

	private CsrfConfigurer<H> csrf(H http) {
		return http.getConfigurer(CsrfConfigurer.class);
	}

	private BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter() {
		BearerTokenAuthenticationFilter filter =
				new BearerTokenAuthenticationFilter(authenticationManager());

		if ( this.resolver != null ) {
			filter.setBearerTokenResolver(this.resolver);
		}

		return filter;
	}

	private AuthenticationManager authenticationManager() {
		return new ProviderManager(
				Arrays.asList(jwtAccessTokenAuthenticationProvider()));
	}

	private AuthenticationProvider jwtAccessTokenAuthenticationProvider() {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);

		Map<String, JwtDecoder> decoders =
				BeanFactoryUtils.beansOfTypeIncludingAncestors(context, JwtDecoder.class);

		if ( !decoders.isEmpty() &&
				this.jwtAccessTokenFormatConfigurer == null ) {
			JwtDecoder decoder = decoders.values().iterator().next();

			this.jwtAccessTokenFormatConfigurer = new JwtAccessTokenFormatConfigurer(decoder);
		}

		if ( !decoders.isEmpty() &&
				this.jwtAccessTokenFormatConfigurer.jwtDecoder.decoder() == null ) {
			JwtDecoder decoder = decoders.values().iterator().next();

			this.jwtAccessTokenFormatConfigurer.jwtDecoder.decoder(decoder);
		}

		JwtAccessTokenAuthenticationProvider provider =
				new JwtAccessTokenAuthenticationProvider(
						this.jwtAccessTokenFormatConfigurer.jwtDecoder.decoder());

		if ( this.jwtAccessTokenFormatConfigurer.populator == null ) {
			Map<String, OAuth2AuthoritiesPopulator> populators =
					BeanFactoryUtils.beansOfTypeIncludingAncestors(context, OAuth2AuthoritiesPopulator.class);

			if ( !populators.isEmpty() ) {
				this.jwtAccessTokenFormatConfigurer.populator = populators.values().iterator().next();
			}
		}

		if ( this.jwtAccessTokenFormatConfigurer.populator == null ) {
			JwtAuthoritiesPopulator populator = new JwtAuthoritiesPopulator();
			if ( StringUtils.hasText(this.jwtAccessTokenFormatConfigurer.scopeAttributeName) ) {
				populator.setScopeAttributeName(this.jwtAccessTokenFormatConfigurer.scopeAttributeName);
			}
			this.jwtAccessTokenFormatConfigurer.populator = populator;
		}

		provider.setAuthoritiesPopulator(this.jwtAccessTokenFormatConfigurer.populator);

		return provider;
	}
}
