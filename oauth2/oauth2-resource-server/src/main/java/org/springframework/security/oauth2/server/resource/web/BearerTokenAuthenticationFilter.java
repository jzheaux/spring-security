/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates requests that contain an OAuth 2.0
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>.
 *
 * This filter should be wired with an {@link AuthenticationManager} that can authenticate
 * a {@link BearerTokenAuthenticationToken}.
 *
 * @author Josh Cummings
 * @author Vedran Pavic
 * @author Joe Grandja
 * @author Jeongjin Kim
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750" target="_blank">The OAuth 2.0
 * Authorization Framework: Bearer Token Usage</a>
 * @see JwtAuthenticationProvider
 */
public final class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

	private final AuthenticationFilter authenticationFilter;

	private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();

	private BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	/**
	 * Construct a {@code BearerTokenAuthenticationFilter} using the provided parameter(s)
	 * @param authenticationManagerResolver
	 */
	public BearerTokenAuthenticationFilter(
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
		Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");
		AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManagerResolver,
				new BearerTokenAuthenticationConverter());
		authenticationFilter.setSuccessHandler((request, response, chain) -> {
		});
		authenticationFilter.setFailureHandler((request, response, exception) -> {
			if (exception instanceof AuthenticationServiceException) {
				throw exception;
			}
			this.authenticationEntryPoint.commence(request, response, exception);
		});
		this.authenticationFilter = authenticationFilter;
	}

	/**
	 * Construct a {@code BearerTokenAuthenticationFilter} using the provided parameter(s)
	 * @param authenticationManager
	 */
	public BearerTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager,
				new BearerTokenAuthenticationConverter());
		authenticationFilter.setSuccessHandler((request, response, chain) -> {
		});
		authenticationFilter.setFailureHandler((request, response, exception) -> {
			if (exception instanceof AuthenticationServiceException) {
				throw exception;
			}
			this.authenticationEntryPoint.commence(request, response, exception);
		});
		this.authenticationFilter = authenticationFilter;
	}

	/**
	 * Extract any
	 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
	 * Token</a> from the request and attempt an authentication.
	 * @param request
	 * @param response
	 * @param filterChain
	 * @throws ServletException
	 * @throws IOException
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		this.authenticationFilter.doFilter(request, response, filterChain);
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.authenticationFilter.setSecurityContextHolderStrategy(securityContextHolderStrategy);
	}

	/**
	 * Sets the {@link SecurityContextRepository} to save the {@link SecurityContext} on
	 * authentication success. The default action is not to save the
	 * {@link SecurityContext}.
	 * @param securityContextRepository the {@link SecurityContextRepository} to use.
	 * Cannot be null.
	 */
	public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.authenticationFilter.setSecurityContextRepository(securityContextRepository);
	}

	public void setAuthenticationEventPublisher(AuthenticationEventPublisher authenticationEventPublisher) {
		this.authenticationFilter.setAuthenticationEventPublisher(authenticationEventPublisher);
	}

	/**
	 * Set the {@link BearerTokenResolver} to use. Defaults to
	 * {@link DefaultBearerTokenResolver}.
	 * @param bearerTokenResolver the {@code BearerTokenResolver} to use
	 */
	public void setBearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
		Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
		this.bearerTokenResolver = bearerTokenResolver;
	}

	/**
	 * Set the {@link AuthenticationEntryPoint} to use. Defaults to
	 * {@link BearerTokenAuthenticationEntryPoint}.
	 * @param authenticationEntryPoint the {@code AuthenticationEntryPoint} to use
	 */
	public void setAuthenticationEntryPoint(final AuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	/**
	 * Set the {@link AuthenticationFailureHandler} to use. Default implementation invokes
	 * {@link AuthenticationEntryPoint}.
	 * @param authenticationFailureHandler the {@code AuthenticationFailureHandler} to use
	 * @since 5.2
	 */
	public void setAuthenticationFailureHandler(final AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFilter.setFailureHandler(authenticationFailureHandler);
	}

	/**
	 * Set the {@link AuthenticationDetailsSource} to use. Defaults to
	 * {@link WebAuthenticationDetailsSource}.
	 * @param authenticationDetailsSource the {@code AuthenticationConverter} to use
	 * @since 5.5
	 */
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	private final class BearerTokenAuthenticationConverter implements AuthenticationConverter {

		@Override
		public Authentication convert(HttpServletRequest request) {
			String token = BearerTokenAuthenticationFilter.this.bearerTokenResolver.resolve(request);
			if (token == null) {
				return null;
			}
			BearerTokenAuthenticationToken authentication = new BearerTokenAuthenticationToken(token);
			Object details = BearerTokenAuthenticationFilter.this.authenticationDetailsSource.buildDetails(request);
			authentication.setDetails(details);
			return authentication;
		}

	}

}
