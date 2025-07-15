/*
 * Copyright 2002-2025 the original author or authors.
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

import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthoritiesGranter;
import org.springframework.security.authorization.AuthoritiesGranterAuthenticationProvider;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.AuthorizationRequestingAccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Adds Step-wise Authentication using {@link AuthorizationManager} and {@link AccessDeniedHandler}.
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured.
 * @author Josh Cummings
 * @since 7.0
 */
public final class AuthorizeStepsConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<AuthorizeStepsConfigurer<H>, H> {

	private int mappingsCount;

	private final AuthorizationRequestingAccessDeniedHandler.Builder accessRequestingBuilder =
			AuthorizationRequestingAccessDeniedHandler.builder();

	private final RequestMatcherDelegatingAuthorizationManager.Builder accessDenyingBuilder =
			RequestMatcherDelegatingAuthorizationManager.builder();

	private final AuthorizationEventPublisher publisher;

	private final ObjectPostProcessor<AuthorizationManager<HttpServletRequest>> postProcessor;

	/**
	 * Creates an instance.
	 * @param context the {@link ApplicationContext} to use
	 */
	public AuthorizeStepsConfigurer(ApplicationContext context) {
		this.publisher = context.getBeanProvider(AuthorizationEventPublisher.class)
				.getIfUnique(() -> new SpringAuthorizationEventPublisher(context));
		ResolvableType type = ResolvableType.forClassWithGenerics(ObjectPostProcessor.class,
				ResolvableType.forClassWithGenerics(AuthorizationManager.class, HttpServletRequest.class));
		ObjectProvider<ObjectPostProcessor<AuthorizationManager<HttpServletRequest>>> provider = context
				.getBeanProvider(type);
		this.postProcessor = provider.getIfUnique(ObjectPostProcessor::identity);
	}

	@Override
	public void configure(H http) {
		if (hasSteps()) {
			this.accessDenyingBuilder.anyRequest().permitAll();
			AuthorizationManager<HttpServletRequest> authorizationManager = this.postProcessor.postProcess(
					this.accessDenyingBuilder.build());
			AuthorizationFilter authorizationFilter = new AuthorizationFilter(authorizationManager);
			authorizationFilter.setAuthorizationEventPublisher(this.publisher);
			authorizationFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
			authorizationFilter.setAccessDeniedHandler(getAccessDeniedHandler());
			http.addFilterAfter(postProcess(authorizationFilter), LogoutFilter.class);
		}
	}

	public AuthorizeStepsConfigurer<H> step(Consumer<AuthorizeStepConfigurer> consumer) {
		consumer.accept(new AuthorizeStepConfigurer());
		return this;
	}

	boolean hasSteps() {
		return this.mappingsCount > 0;
	}

	<T> AuthorizationManager<T> isAuthenticated() {
		return AuthorityAuthorizationManager.hasAuthority("authenticated");
	}

	AuthorizationRequestingAccessDeniedHandler getAccessDeniedHandler() {
		return this.accessRequestingBuilder.build();
	}

	public final class AuthorizeStepConfigurer {

		public AuthorizeRequestingConfigurer entryPoint(AuthenticationEntryPoint entryPoint, Consumer<AuthenticationManager> managerConsumer) {
			return new AuthorizeRequestingConfigurer(entryPoint, managerConsumer);
		}

		public AuthorizeEndpointConfigurer endpoint(RequestMatcher matcher) {
			return new AuthorizeEndpointConfigurer(matcher);
		}

		public final class AuthorizeRequestingConfigurer {
			private final AuthenticationEntryPoint entryPoint;
			private final Consumer<AuthenticationManager> managerConsumer;

			private AuthorizeRequestingConfigurer(AuthenticationEntryPoint entryPoint,
					Consumer<AuthenticationManager> managerConsumer) {
				this.entryPoint = entryPoint;
				this.managerConsumer = managerConsumer;
			}

			AuthorizeStepConfigurer grants(AuthoritiesGranter granter) {
				AuthorizeStepsConfigurer.this.accessRequestingBuilder.add(granter, this.entryPoint);
				AuthenticationManager manager = AuthorizeStepsConfigurer.this.getBuilder().getSharedObject(AuthenticationManager.class);
				this.managerConsumer.accept(new AuthoritiesGranterAuthenticationProvider(manager, granter));
				return AuthorizeStepConfigurer.this;
			}
		}

		public final class AuthorizeEndpointConfigurer {
			private final RequestMatcher requestMatcher;

			AuthorizeEndpointConfigurer(RequestMatcher requestMatcher) {
				this.requestMatcher = requestMatcher;
			}

			AuthorizeStepConfigurer needs(AuthorizationManager<RequestAuthorizationContext> manager) {
				AuthorizeStepsConfigurer.this.mappingsCount++;
				AuthorizeStepsConfigurer.this.accessDenyingBuilder.add(this.requestMatcher, manager);
				return AuthorizeStepConfigurer.this;
			}
		}
	}
}
