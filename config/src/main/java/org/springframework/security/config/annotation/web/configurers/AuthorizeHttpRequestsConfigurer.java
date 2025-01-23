/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.servlet.util.matcher.ServletPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;
import org.springframework.util.function.SingletonSupplier;

/**
 * Adds a URL based authorization using {@link AuthorizationManager}.
 *
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured.
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class AuthorizeHttpRequestsConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<AuthorizeHttpRequestsConfigurer<H>, H> {

	static final AuthorizationManager<RequestAuthorizationContext> permitAllAuthorizationManager = (a,
			o) -> new AuthorizationDecision(true);

	private final AuthorizationManagerRequestMatcherRegistry registry;

	private final AuthorizationEventPublisher publisher;

	private final Supplier<RoleHierarchy> roleHierarchy;

	private String rolePrefix = "ROLE_";

	private ObjectPostProcessor<AuthorizationManager<HttpServletRequest>> postProcessor = ObjectPostProcessor
		.identity();

	/**
	 * Creates an instance.
	 * @param context the {@link ApplicationContext} to use
	 */
	public AuthorizeHttpRequestsConfigurer(ApplicationContext context) {
		this.registry = new AuthorizationManagerRequestMatcherRegistry(context);
		if (context.getBeanNamesForType(AuthorizationEventPublisher.class).length > 0) {
			this.publisher = context.getBean(AuthorizationEventPublisher.class);
		}
		else {
			this.publisher = new SpringAuthorizationEventPublisher(context);
		}
		this.roleHierarchy = SingletonSupplier.of(() -> (context.getBeanNamesForType(RoleHierarchy.class).length > 0)
				? context.getBean(RoleHierarchy.class) : new NullRoleHierarchy());
		String[] grantedAuthorityDefaultsBeanNames = context.getBeanNamesForType(GrantedAuthorityDefaults.class);
		if (grantedAuthorityDefaultsBeanNames.length > 0) {
			GrantedAuthorityDefaults grantedAuthorityDefaults = context.getBean(GrantedAuthorityDefaults.class);
			this.rolePrefix = grantedAuthorityDefaults.getRolePrefix();
		}
		ResolvableType type = ResolvableType.forClassWithGenerics(ObjectPostProcessor.class,
				ResolvableType.forClassWithGenerics(AuthorizationManager.class, HttpServletRequest.class));
		ObjectProvider<ObjectPostProcessor<AuthorizationManager<HttpServletRequest>>> provider = context
			.getBeanProvider(type);
		provider.ifUnique((postProcessor) -> this.postProcessor = postProcessor);
	}

	/**
	 * The {@link AuthorizationManagerRequestMatcherRegistry} is what users will interact
	 * with after applying the {@link AuthorizeHttpRequestsConfigurer}.
	 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
	 * customizations
	 */
	public AuthorizationManagerRequestMatcherRegistry getRegistry() {
		return this.registry;
	}

	@Override
	public void configure(H http) {
		AuthorizationManager<HttpServletRequest> authorizationManager = this.registry.createAuthorizationManager();
		AuthorizationFilter authorizationFilter = new AuthorizationFilter(authorizationManager);
		authorizationFilter.setAuthorizationEventPublisher(this.publisher);
		authorizationFilter.setShouldFilterAllDispatcherTypes(this.registry.shouldFilterAllDispatcherTypes);
		authorizationFilter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		http.addFilter(postProcess(authorizationFilter));
	}

	private AuthorizationManagerRequestMatcherRegistry addMapping(List<? extends RequestMatcher> matchers,
			AuthorizationManager<RequestAuthorizationContext> manager) {
		for (RequestMatcher matcher : matchers) {
			this.registry.addMapping(matcher, manager);
		}
		return this.registry;
	}

	AuthorizationManagerRequestMatcherRegistry addFirst(RequestMatcher matcher,
			AuthorizationManager<RequestAuthorizationContext> manager) {
		this.registry.addFirst(matcher, manager);
		return this.registry;
	}

	public interface ServletRequestMatcherRegistryOperations {

		ServletRequestMatcherRegistryOperations defaultServlet(Consumer<ServletRequestMatcherRegistry> registrar);

		ServletRequestMatcherRegistryOperations servlet(String pattern,
				Consumer<ServletRequestMatcherRegistry> registrar);

	}

	/**
	 * Registry for mapping a {@link RequestMatcher} to an {@link AuthorizationManager}.
	 *
	 * @author Evgeniy Cheban
	 */
	public final class AuthorizationManagerRequestMatcherRegistry extends AbstractRequestMatcherRegistry<AuthorizedUrl>
			implements ServletRequestMatcherRegistryOperations {

		private final RequestMatcherDelegatingAuthorizationManager.Builder managerBuilder = RequestMatcherDelegatingAuthorizationManager
			.builder();

		private final Map<String, ServletRequestMatcherRegistry> servletPattern = new LinkedHashMap<>();

		private List<RequestMatcher> unmappedMatchers;

		private int mappingCount;

		private boolean shouldFilterAllDispatcherTypes = true;

		private AuthorizationManagerRequestMatcherRegistry(ApplicationContext context) {
			setApplicationContext(context);
		}

		private void addMapping(RequestMatcher matcher, AuthorizationManager<RequestAuthorizationContext> manager) {
			Assert.isTrue(this.servletPattern.isEmpty(),
					"Since you have used #servlet, all request matchers must be configured using #servletPath; alternatively, you can use requestMatchers(RequestMatcher) for all requests.");
			this.unmappedMatchers = null;
			this.managerBuilder.add(matcher, manager);
			this.mappingCount++;
		}

		private void addFirst(RequestMatcher matcher, AuthorizationManager<RequestAuthorizationContext> manager) {
			Assert.isTrue(this.servletPattern.isEmpty(),
					"Since you have used #servlet, all request matchers must be configured using #servletPath; alternatively, you can use requestMatchers(RequestMatcher) for all requests.");
			this.unmappedMatchers = null;
			this.managerBuilder.mappings((m) -> m.add(0, new RequestMatcherEntry<>(matcher, manager)));
			this.mappingCount++;
		}

		private AuthorizationManager<HttpServletRequest> servletAuthorizationManager() {
			for (Map.Entry<String, ServletRequestMatcherRegistry> entry : this.servletPattern.entrySet()) {
				RequestMatcher matcher = new ServletPatternRequestMatcher(entry.getKey());
				ServletRequestMatcherRegistry registry = entry.getValue();
				AuthorizationManager<RequestAuthorizationContext> manager = registry.authorizationManager();
				this.managerBuilder.add(matcher, manager);
			}
			return postProcess(this.managerBuilder.build());
		}

		private AuthorizationManager<HttpServletRequest> authorizationManager() {
			Assert.state(this.unmappedMatchers == null,
					() -> "An incomplete mapping was found for " + this.unmappedMatchers
							+ ". Try completing it with something like requestUrls().<something>.hasRole('USER')");
			Assert.state(this.mappingCount > 0,
					"At least one mapping is required (for example, authorizeHttpRequests().anyRequest().authenticated())");
			return postProcess(this.managerBuilder.build());
		}

		private AuthorizationManager<HttpServletRequest> createAuthorizationManager() {
			AuthorizationManager<HttpServletRequest> manager = (this.servletPattern.isEmpty()) ? authorizationManager()
					: servletAuthorizationManager();
			return AuthorizeHttpRequestsConfigurer.this.postProcessor.postProcess(manager);
		}

		@Override
		public ServletRequestMatcherRegistryOperations defaultServlet(
				Consumer<ServletRequestMatcherRegistry> registrar) {
			return servlet("/", registrar);
		}

		@Override
		public ServletRequestMatcherRegistryOperations servlet(String pattern,
				Consumer<ServletRequestMatcherRegistry> registrar) {
			ServletRequestMatcherRegistry registry = new ServletRequestMatcherRegistry(
					AuthorizeHttpRequestsConfigurer.this, pattern);
			this.servletPattern.put(pattern, registry);
			registrar.accept(registry);
			return this;
		}

		@Override
		protected AuthorizedUrl chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			this.unmappedMatchers = requestMatchers;
			return new AuthorizedUrl(this,
					(manager) -> AuthorizeHttpRequestsConfigurer.this.addMapping(requestMatchers, manager));
		}

		/**
		 * Adds an {@link ObjectPostProcessor} for this class.
		 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		public AuthorizationManagerRequestMatcherRegistry withObjectPostProcessor(
				ObjectPostProcessor<?> objectPostProcessor) {
			addObjectPostProcessor(objectPostProcessor);
			return this;
		}

		/**
		 * @deprecated
		 */
		@Deprecated(since = "6.4", forRemoval = true)
		public AuthorizationManagerRequestMatcherRegistry withObjectPostProcessor(
				org.springframework.security.config.annotation.ObjectPostProcessor<?> objectPostProcessor) {
			addObjectPostProcessor(objectPostProcessor);
			return this;
		}

		/**
		 * Sets whether all dispatcher types should be filtered.
		 * @param shouldFilter should filter all dispatcher types. Default is {@code true}
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 * @since 5.7
		 * @deprecated Permit access to the {@link jakarta.servlet.DispatcherType}
		 * instead. <pre>
		 * &#064;Configuration
		 * &#064;EnableWebSecurity
		 * public class SecurityConfig {
		 *
		 * 	&#064;Bean
		 * 	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		 * 		http
		 * 		 	.authorizeHttpRequests((authorize) -&gt; authorize
		 * 				.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
		 * 			 	// ...
		 * 		 	);
		 * 		return http.build();
		 * 	}
		 * }
		 * </pre>
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public AuthorizationManagerRequestMatcherRegistry shouldFilterAllDispatcherTypes(boolean shouldFilter) {
			this.shouldFilterAllDispatcherTypes = shouldFilter;
			return this;
		}

		/**
		 * Return the {@link HttpSecurityBuilder} when done using the
		 * {@link AuthorizeHttpRequestsConfigurer}. This is useful for method chaining.
		 * @return the {@link HttpSecurityBuilder} for further customizations
		 * @deprecated For removal in 7.0. Use the lambda based configuration instead.
		 */
		@Deprecated(since = "6.1", forRemoval = true)
		public H and() {
			return AuthorizeHttpRequestsConfigurer.this.and();
		}

	}

	public static final class ServletRequestMatcherRegistry {

		private final AuthorizeHttpRequestsConfigurer<?> configurer;

		private final RequestMatcherDelegatingAuthorizationManager.Builder managers = RequestMatcherDelegatingAuthorizationManager
			.builder();

		private final String servletPath;

		private List<RequestMatcher> unmappedMatchers;

		ServletRequestMatcherRegistry(AuthorizeHttpRequestsConfigurer<?> configurer, String pattern) {
			this.configurer = configurer;
			boolean isPathPattern = pattern.startsWith("/") && pattern.endsWith("/*");
			this.servletPath = (isPathPattern) ? pattern.substring(0, pattern.length() - 2) : null;
		}

		public AuthorizedServlet patterns(HttpMethod method, String... patterns) {
			List<RequestMatcher> matchers = new ArrayList<>();
			for (String pattern : patterns) {
				String uriPattern = (this.servletPath != null) ? this.servletPath + pattern : pattern;
				matchers.add(PathPatternRequestMatcher.builder().pattern(method, uriPattern));
			}
			return new AuthorizedServlet(this.configurer, (manager) -> addMapping(matchers, manager));
		}

		public AuthorizedServlet pattern(HttpMethod method, String pattern) {
			return patterns(method, pattern);
		}

		public AuthorizedServlet patterns(String... patterns) {
			return patterns(null, patterns);
		}

		public AuthorizedServlet pattern(String pattern) {
			return patterns((HttpMethod) null, pattern);
		}

		public AuthorizedServlet anyRequest() {
			return patterns((HttpMethod) null, "/**");
		}

		AuthorizationManager<RequestAuthorizationContext> authorizationManager() {
			Assert.state(this.unmappedMatchers == null,
					() -> "An incomplete mapping was found for " + this.unmappedMatchers
							+ ". Try completing it with something like requestUrls().<something>.hasRole('USER')");
			AuthorizationManager<HttpServletRequest> request = this.managers.build();
			return (authentication, context) -> request.check(authentication, context.getRequest());

		}

		private void addMapping(List<RequestMatcher> matchers,
				AuthorizationManager<RequestAuthorizationContext> manager) {
			this.unmappedMatchers = null;
			for (RequestMatcher matcher : matchers) {
				this.managers.add(matcher, manager);
			}
		}

	}

	interface AuthorizationBuilder<B> {

		default B permitAll() {
			return access(permitAllAuthorizationManager);
		}

		/**
		 * Specify that URLs are not allowed by anyone.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		default B denyAll() {
			return access((a, o) -> new AuthorizationDecision(false));
		}

		/**
		 * Specifies a user requires a role.
		 * @param role the role that should be required which is prepended with ROLE_
		 * automatically (i.e. USER, ADMIN, etc). It should not start with ROLE_
		 * @return {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		default B hasRole(String role) {
			return access(AuthorityAuthorizationManager.hasAnyRole("ROLE_", new String[] { role }));
		}

		/**
		 * Specifies that a user requires one of many roles.
		 * @param roles the roles that the user should have at least one of (i.e. ADMIN,
		 * USER, etc). Each role should not start with ROLE_ since it is automatically
		 * prepended already
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		default B hasAnyRole(String... roles) {
			return access(AuthorityAuthorizationManager.hasAnyRole("ROLE_", roles));
		}

		/**
		 * Specifies a user requires an authority.
		 * @param authority the authority that should be required
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		default B hasAuthority(String authority) {
			return access(AuthorityAuthorizationManager.hasAuthority(authority));
		}

		/**
		 * Specifies that a user requires one of many authorities.
		 * @param authorities the authorities that the user should have at least one of
		 * (i.e. ROLE_USER, ROLE_ADMIN, etc)
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		default B hasAnyAuthority(String... authorities) {
			return access(AuthorityAuthorizationManager.hasAnyAuthority(authorities));
		}

		/**
		 * Specify that URLs are allowed by any authenticated user.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		default B authenticated() {
			return access(AuthenticatedAuthorizationManager.authenticated());
		}

		/**
		 * Specify that URLs are allowed by users who have authenticated and were not
		 * "remembered".
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 * @see RememberMeConfigurer
		 */
		default B fullyAuthenticated() {
			return access(AuthenticatedAuthorizationManager.fullyAuthenticated());
		}

		/**
		 * Specify that URLs are allowed by users that have been remembered.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 * @see RememberMeConfigurer
		 */
		default B rememberMe() {
			return access(AuthenticatedAuthorizationManager.rememberMe());
		}

		/**
		 * Specify that URLs are allowed by anonymous users.
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customization
		 * @since 5.8
		 */
		default B anonymous() {
			return access(AuthenticatedAuthorizationManager.anonymous());
		}

		/**
		 * Allows specifying a custom {@link AuthorizationManager}.
		 * @param manager the {@link AuthorizationManager} to use
		 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
		 * customizations
		 */
		B access(AuthorizationManager<RequestAuthorizationContext> manager);

	}

	public abstract static class AbstractAuthorizationBuilder<B, A extends AbstractAuthorizationBuilder<B, A>>
			implements AuthorizationBuilder<B> {

		private final AuthorizeHttpRequestsConfigurer<?> configurer;

		private final B registry;

		private final Consumer<AuthorizationManager<RequestAuthorizationContext>> consumer;

		private boolean not;

		AbstractAuthorizationBuilder(B registry, AuthorizeHttpRequestsConfigurer<?> configurer,
				Consumer<AuthorizationManager<RequestAuthorizationContext>> consumer) {
			this.registry = registry;
			this.configurer = configurer;
			this.consumer = consumer;
		}

		/**
		 * Negates the following authorization rule.
		 * @return the {@link AuthorizedUrl} for further customization
		 * @since 6.3
		 */
		public A not() {
			this.not = true;
			return (A) this;
		}

		@Override
		public B hasRole(String role) {
			return access(withRoleHierarchy(
					AuthorityAuthorizationManager.hasAnyRole(this.configurer.rolePrefix, new String[] { role })));
		}

		@Override
		public B hasAnyRole(String... roles) {
			return access(
					withRoleHierarchy(AuthorityAuthorizationManager.hasAnyRole(this.configurer.rolePrefix, roles)));
		}

		@Override
		public B hasAuthority(String authority) {
			return access(withRoleHierarchy(AuthorityAuthorizationManager.hasAuthority(authority)));
		}

		@Override
		public B hasAnyAuthority(String... authorities) {
			return access(withRoleHierarchy(AuthorityAuthorizationManager.hasAnyAuthority(authorities)));
		}

		private AuthorityAuthorizationManager<RequestAuthorizationContext> withRoleHierarchy(
				AuthorityAuthorizationManager<RequestAuthorizationContext> manager) {
			manager.setRoleHierarchy(this.configurer.roleHierarchy.get());
			return manager;
		}

		/**
		 * Specify that a path variable in URL to be compared.
		 *
		 * <p>
		 * For example, <pre>
		 * requestMatchers("/user/{username}").hasVariable("username").equalTo(Authentication::getName)
		 * </pre>
		 * @param variable the variable in URL template to compare.
		 * @return {@link AuthorizedUrl.AuthorizedUrlVariable} for further customization.
		 * @since 6.3
		 */
		public AuthorizedUrlVariable hasVariable(String variable) {
			return new AuthorizedUrlVariable(variable);
		}

		@Override
		public B access(AuthorizationManager<RequestAuthorizationContext> manager) {
			Assert.notNull(manager, "manager cannot be null");
			if (this.not) {
				this.consumer.accept(AuthorizationManagers.not(manager));
			}
			else {
				this.consumer.accept(manager);
			}
			return this.registry;
		}

		/**
		 * An object that allows configuring {@link RequestMatcher}s with URI path
		 * variables
		 *
		 * @author Taehong Kim
		 * @since 6.3
		 */
		public final class AuthorizedUrlVariable {

			private final String variable;

			private AuthorizedUrlVariable(String variable) {
				this.variable = variable;
			}

			/**
			 * Compares the value of a path variable in the URI with an `Authentication`
			 * attribute
			 * <p>
			 * For example, <pre>
			 * requestMatchers("/user/{username}").hasVariable("username").equalTo(Authentication::getName));
			 * </pre>
			 * @param function a function to get value from {@link Authentication}.
			 * @return the {@link AuthorizationManagerRequestMatcherRegistry} for further
			 * customization.
			 */
			public B equalTo(Function<Authentication, String> function) {
				return access((auth, requestContext) -> {
					String value = requestContext.getVariables().get(this.variable);
					return new AuthorizationDecision(function.apply(auth.get()).equals(value));
				});
			}

		}

	}

	public static final class AuthorizedServlet extends AbstractAuthorizationBuilder<Void, AuthorizedServlet> {

		AuthorizedServlet(AuthorizeHttpRequestsConfigurer<?> configurer,
				Consumer<AuthorizationManager<RequestAuthorizationContext>> consumer) {
			super(null, configurer, consumer);
		}

	}

	/**
	 * An object that allows configuring the {@link AuthorizationManager} for
	 * {@link RequestMatcher}s.
	 *
	 * @author Evgeniy Cheban
	 * @author Josh Cummings
	 */
	public class AuthorizedUrl
			extends AbstractAuthorizationBuilder<AuthorizationManagerRequestMatcherRegistry, AuthorizedUrl> {

		AuthorizedUrl(AuthorizationManagerRequestMatcherRegistry registry,
				Consumer<AuthorizationManager<RequestAuthorizationContext>> consumer) {
			super(registry, AuthorizeHttpRequestsConfigurer.this, consumer);
		}

	}

}
