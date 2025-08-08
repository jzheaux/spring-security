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

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AlwaysAuthoritiesGranter;
import org.springframework.security.authorization.AuthoritiesGranter;
import org.springframework.security.authorization.AuthoritiesGranterAuthenticationManager;
import org.springframework.security.authorization.CompositeAuthoritiesGranter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.AuthorizationEntryPoint;
import org.springframework.security.web.SimpleAuthorizationEntryPoint;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * Adds HTTP basic based authentication. All attributes have reasonable defaults making
 * all parameters are optional.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link BasicAuthenticationFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * <ul>
 * <li>AuthenticationEntryPoint - populated with the
 * {@link #authenticationEntryPoint(AuthenticationEntryPoint)} (default
 * {@link BasicAuthenticationEntryPoint})</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link AuthenticationManager}</li>
 * <li>{@link RememberMeServices}</li>
 * </ul>
 *
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @since 3.2
 */
public final class HttpBasicConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<HttpBasicConfigurer<B>, B>
		implements DefaultAuthorityAuthorizableConfigurer<HttpBasicConfigurer<B>> {

	private static final RequestHeaderRequestMatcher X_REQUESTED_WITH = new RequestHeaderRequestMatcher(
			"X-Requested-With", "XMLHttpRequest");

	private static final String DEFAULT_REALM = "Realm";

	private AuthoritiesGranter authoritiesGranters = new AlwaysAuthoritiesGranter(defaultAuthority());

	private Integer factorOrder;

	private AuthenticationEntryPoint authenticationEntryPoint;

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	private BasicAuthenticationEntryPoint basicAuthEntryPoint = new BasicAuthenticationEntryPoint();

	private SecurityContextRepository securityContextRepository;

	/**
	 * Creates a new instance
	 * @see HttpSecurity#httpBasic(Customizer)
	 */
	public HttpBasicConfigurer() {
		realmName(DEFAULT_REALM);
		LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
		entryPoints.put(X_REQUESTED_WITH, new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
		DelegatingAuthenticationEntryPoint defaultEntryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
		defaultEntryPoint.setDefaultEntryPoint(this.basicAuthEntryPoint);
		this.authenticationEntryPoint = defaultEntryPoint;
	}

	/**
	 * Allows easily changing the realm, but leaving the remaining defaults in place. If
	 * {@link #authenticationEntryPoint(AuthenticationEntryPoint)} has been invoked,
	 * invoking this method will result in an error.
	 * @param realmName the HTTP Basic realm to use
	 * @return {@link HttpBasicConfigurer} for additional customization
	 */
	public HttpBasicConfigurer<B> realmName(String realmName) {
		this.basicAuthEntryPoint.setRealmName(realmName);
		this.basicAuthEntryPoint.afterPropertiesSet();
		return this;
	}

	/**
	 * The {@link AuthenticationEntryPoint} to be populated on
	 * {@link BasicAuthenticationFilter} in the event that authentication fails. The
	 * default to use {@link BasicAuthenticationEntryPoint} with the realm "Realm".
	 * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use
	 * @return {@link HttpBasicConfigurer} for additional customization
	 */
	public HttpBasicConfigurer<B> authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		return this;
	}

	/**
	 * Specifies a custom {@link AuthenticationDetailsSource} to use for basic
	 * authentication. The default is {@link WebAuthenticationDetailsSource}.
	 * @param authenticationDetailsSource the custom {@link AuthenticationDetailsSource}
	 * to use
	 * @return {@link HttpBasicConfigurer} for additional customization
	 */
	public HttpBasicConfigurer<B> authenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
		return this;
	}

	/**
	 * Specifies a custom {@link SecurityContextRepository} to use for basic
	 * authentication. The default is {@link RequestAttributeSecurityContextRepository}.
	 * @param securityContextRepository the custom {@link SecurityContextRepository} to
	 * use
	 * @return {@link HttpBasicConfigurer} for additional customization
	 * @since 6.1
	 */
	public HttpBasicConfigurer<B> securityContextRepository(SecurityContextRepository securityContextRepository) {
		this.securityContextRepository = securityContextRepository;
		return this;
	}

	@Override
	public HttpBasicConfigurer<B> factor(Integer order) {
		this.factorOrder = order;
		return this;
	}

	@Override
	public HttpBasicConfigurer<B> grants(AuthoritiesGranter granter) {
		this.authoritiesGranters = new CompositeAuthoritiesGranter(this.authoritiesGranters, granter);
		return this;
	}

	@Override
	public String defaultAuthority() {
		return "AUTHN_BASIC";
	}

	@Override
	public void init(B http) {
		registerDefaults(http);
		if (this.factorOrder == null) {
			return;
		}
		ExceptionHandlingConfigurer<B> exceptions = http.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptions != null) {
			AuthorizationEntryPoint entryPoint = new SimpleAuthorizationEntryPoint(this.authenticationEntryPoint,
					this.factorOrder, this.authoritiesGranters);
			exceptions.authorizationEntryPoint((e) -> e.add(entryPoint));
		}
		AuthorizeHttpRequestsConfigurer<B> authorize = http.getConfigurer(AuthorizeHttpRequestsConfigurer.class);
		if (authorize != null) {
			authorize.getRegistry().withDefaultAuthority(defaultAuthority());
		}
	}

	private void registerDefaults(B http) {
		ContentNegotiationStrategy contentNegotiationStrategy = http.getSharedObject(ContentNegotiationStrategy.class);
		if (contentNegotiationStrategy == null) {
			contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
		}
		MediaTypeRequestMatcher restMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy,
				MediaType.APPLICATION_ATOM_XML, MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
				MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML, MediaType.MULTIPART_FORM_DATA,
				MediaType.TEXT_XML);
		restMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		MediaTypeRequestMatcher allMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy, MediaType.ALL);
		allMatcher.setUseEquals(true);
		RequestMatcher notHtmlMatcher = new NegatedRequestMatcher(
				new MediaTypeRequestMatcher(contentNegotiationStrategy, MediaType.TEXT_HTML));
		RequestMatcher restNotHtmlMatcher = new AndRequestMatcher(Arrays.asList(notHtmlMatcher, restMatcher));
		RequestMatcher preferredMatcher = new OrRequestMatcher(
				Arrays.asList(X_REQUESTED_WITH, restNotHtmlMatcher, allMatcher));
		registerDefaultEntryPoint(http, preferredMatcher);
		registerDefaultLogoutSuccessHandler(http, preferredMatcher);
	}

	private void registerDefaultEntryPoint(B http, RequestMatcher preferredMatcher) {
		ExceptionHandlingConfigurer<B> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}
		exceptionHandling.defaultAuthenticationEntryPointFor(postProcess(this.authenticationEntryPoint),
				preferredMatcher);
	}

	private void registerDefaultLogoutSuccessHandler(B http, RequestMatcher preferredMatcher) {
		LogoutConfigurer<B> logout = http.getConfigurer(LogoutConfigurer.class);
		if (logout == null) {
			return;
		}
		LogoutConfigurer<B> handler = logout.defaultLogoutSuccessHandlerFor(
				postProcess(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT)), preferredMatcher);
	}

	private AuthenticationManager getAuthenticationManager(B http) {
		if (this.factorOrder == null) {
			return http.getSharedObject(AuthenticationManager.class);
		}
		return new AuthoritiesGranterAuthenticationManager(http.getSharedObject(AuthenticationManager.class),
				this.authoritiesGranters);
	}

	@Override
	public void configure(B http) {
		AuthenticationManager authenticationManager = getAuthenticationManager(http);
		BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(authenticationManager,
				this.authenticationEntryPoint);
		if (this.authenticationDetailsSource != null) {
			basicAuthenticationFilter.setAuthenticationDetailsSource(this.authenticationDetailsSource);
		}
		if (this.securityContextRepository != null) {
			basicAuthenticationFilter.setSecurityContextRepository(this.securityContextRepository);
		}
		RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
		if (rememberMeServices != null) {
			basicAuthenticationFilter.setRememberMeServices(rememberMeServices);
		}
		basicAuthenticationFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		basicAuthenticationFilter = postProcess(basicAuthenticationFilter);
		http.addFilter(basicAuthenticationFilter);
	}

}
