/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import java.time.Duration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthoritiesGranter;
import org.springframework.security.authorization.AuthoritiesGranterAuthenticationManager;
import org.springframework.security.authorization.CompositeAuthoritiesGranter;
import org.springframework.security.authorization.PreAuthenticatedAuthoritiesGranter;
import org.springframework.security.authorization.SimpleAuthoritiesGranter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SimpleAuthorizationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

public final class MfaConfigurer<B extends HttpSecurityBuilder<B>>
		implements SecurityConfigurer<DefaultSecurityFilterChain, B> {

	private final Customizer<AuthorizeHttpRequestsConfigurer<B>> authorize;

	private final Customizer<ExceptionHandlingConfigurer<B>> exceptions;

	private AuthenticationEntryPoint entryPoint = new Http403ForbiddenEntryPoint();

	private AuthoritiesGranter authoritiesGranter;

	public MfaConfigurer(String authority, SecurityConfigurerAdapter<?, B> configurer) {
		this.authoritiesGranter = new SimpleAuthoritiesGranter(authority);
		this.authorize = (a) -> a.getRegistry().withDefaultAuthority(authority);
		this.exceptions = (e) -> e.authorizationEntryPoint(
				(p) -> p.add(new SimpleAuthorizationEntryPoint(this.entryPoint, this.authoritiesGranter)));
		configurer.addObjectPostProcessor(new ObjectPostProcessor<AuthenticationManager>() {
			@Override
			public AuthenticationManager postProcess(AuthenticationManager object) {
				return new AuthoritiesGranterAuthenticationManager(object, MfaConfigurer.this.authoritiesGranter);
			}
		});
	}

	public MfaConfigurer<B> authenticationEntryPoint(AuthenticationEntryPoint entryPoint) {
		this.entryPoint = entryPoint;
		return this;
	}

	public MfaConfigurer<B> grants(AuthoritiesGranter granter) {
		this.authoritiesGranter = new CompositeAuthoritiesGranter(this.authoritiesGranter, granter);
		return this;
	}

	public MfaConfigurer<B> grants(String... authority) {
		return grants(new SimpleAuthoritiesGranter(authority));
	}

	public MfaConfigurer<B> grants(Duration duration, String... authority) {
		return grants(new SimpleAuthoritiesGranter(duration, authority));
	}

	@Override
	public void init(B http) {
		SecurityContextHolderStrategy strategy = http.getSharedObjectProvider(SecurityContextHolderStrategy.class)
			.getIfUnique(SecurityContextHolder::getContextHolderStrategy);
		grants(new PreAuthenticatedAuthoritiesGranter(strategy));
		this.authorize.customize(http.getConfigurer(AuthorizeHttpRequestsConfigurer.class));
		this.exceptions.customize(http.getConfigurer(ExceptionHandlingConfigurer.class));
	}

	@Override
	public void configure(B builder) throws Exception {

	}

}
