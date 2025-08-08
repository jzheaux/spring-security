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

import java.util.function.Function;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AlwaysAuthoritiesGranter;
import org.springframework.security.authorization.AuthoritiesGranter;
import org.springframework.security.authorization.AuthoritiesGranterAuthenticationManager;
import org.springframework.security.authorization.CompositeAuthoritiesGranter;
import org.springframework.security.authorization.PreAuthenticatedAuthoritiesGranter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SimpleAuthorizationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

public final class MfaConfigurer<B extends HttpSecurityBuilder<B>, C> extends
		AbstractHttpConfigurer<HttpBasicConfigurer<B>, B> implements AuthorizableConfigurer<MfaConfigurer<B, C>> {

	private final String authority;

	private Customizer<AuthorizeHttpRequestsConfigurer<B>> authorize = Customizer.withDefaults();

	private Customizer<ExceptionHandlingConfigurer<B>> exceptions = Customizer.withDefaults();

	private Function<AuthenticationManager, AuthenticationManager> managerPostProcessor = Function.identity();

	private AuthenticationEntryPoint entryPoint = new Http403ForbiddenEntryPoint();

	private AuthoritiesGranter authoritiesGranter;

	public MfaConfigurer(String authority) {
		this.authority = authority;
		this.authoritiesGranter = new AlwaysAuthoritiesGranter(authority);
	}

	@Override
	public void init(B http) {
		setBuilder(http);
		grants(new PreAuthenticatedAuthoritiesGranter(getSecurityContextHolderStrategy()));
		this.authorize.customize(http.getConfigurer(AuthorizeHttpRequestsConfigurer.class));
		this.exceptions.customize(http.getConfigurer(ExceptionHandlingConfigurer.class));
	}

	public AuthenticationManager postProcess(AuthenticationManager manager) {
		return this.managerPostProcessor.apply(manager);
	}

	public MfaConfigurer<B, C> authenticationEntryPoint(AuthenticationEntryPoint entryPoint) {
		this.entryPoint = entryPoint;
		return this;
	}

	@Override
	public MfaConfigurer<B, C> grants(AuthoritiesGranter granter) {
		this.authoritiesGranter = new CompositeAuthoritiesGranter(this.authoritiesGranter, granter);
		return this;
	}

	@Override
	public MfaConfigurer<B, C> factor(Integer order) {
		this.exceptions = (e) -> e.authorizationEntryPoint(
				(p) -> p.add(new SimpleAuthorizationEntryPoint(this.entryPoint, order, this.authoritiesGranter)));
		this.authorize = (a) -> a.getRegistry().withDefaultAuthority(this.authority);
		this.managerPostProcessor = (m) -> {
			SecurityContextHolderStrategy strategy = getSecurityContextHolderStrategy();
			grants(new PreAuthenticatedAuthoritiesGranter(strategy));
			return new AuthoritiesGranterAuthenticationManager(m, this.authoritiesGranter);
		};
		return this;
	}

}
