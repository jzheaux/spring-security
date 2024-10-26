/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.access.intercept;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

/**
 * An {@link AuthorizationManager} which delegates to a specific
 * {@link AuthorizationManager} based on a {@link RequestMatcher} evaluation.
 *
 * @author Evgeniy Cheban
 * @author Parikshit Dutta
 * @since 5.5
 */
public final class RequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<HttpServletRequest> {

	private static final AuthorizationDecision DENY = new AuthorizationDecision(false);

	private final Log logger = LogFactory.getLog(getClass());

	private final List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;

	private RequestMatcherDelegatingAuthorizationManager(
			List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings) {
		Assert.notEmpty(mappings, "mappings cannot be empty");
		this.mappings = mappings;
	}

	/**
	 * Delegates to a specific {@link AuthorizationManager} based on a
	 * {@link RequestMatcher} evaluation.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param request the {@link HttpServletRequest} to check
	 * @return an {@link AuthorizationDecision}. If there is no {@link RequestMatcher}
	 * matching the request, or the {@link AuthorizationManager} could not decide, then
	 * null is returned
	 * @deprecated please use {@link #authorize(Supplier, Object)} instead
	 */
	@Deprecated
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Authorizing %s", requestLine(request)));
		}
		for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {

			RequestMatcher matcher = mapping.getRequestMatcher();
			MatchResult matchResult = matcher.matcher(request);
			if (matchResult.isMatch()) {
				AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(
							LogMessage.format("Checking authorization on %s using %s", requestLine(request), manager));
				}
				return manager.check(authentication,
						new RequestAuthorizationContext(request, matchResult.getVariables()));
			}
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.of(() -> "Denying request since did not find matching RequestMatcher"));
		}
		return DENY;
	}

	private static String requestLine(HttpServletRequest request) {
		return request.getMethod() + " " + UrlUtils.buildRequestUrl(request);
	}

	/**
	 * Creates a builder for {@link RequestMatcherDelegatingAuthorizationManager}.
	 * @return the new {@link Builder} instance
	 */
	public static Builder<?> builder() {
		return new Builder<>();
	}

	public static ServletBuilder<?> builder(ServletContext servletContext) {
		if (!mvcPresent) {
			return new AntServletBuilder();
		}
		if (servletContext == null) {
			return new AntServletBuilder();
		}
		WebApplicationContext context = WebApplicationContextUtils.getWebApplicationContext(servletContext);
		if (context == null) {
			return new AntServletBuilder();
		}
		return new ServletSelectingServletBuilder();
	}

	/**
	 * A builder for {@link RequestMatcherDelegatingAuthorizationManager}.
	 */
	public static class Builder<B extends Builder<B>> {

		private boolean anyRequestConfigured;

		private final List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings = new ArrayList<>();

		/**
		 * Maps a {@link RequestMatcher} to an {@link AuthorizationManager}.
		 * @param matcher the {@link RequestMatcher} to use
		 * @param manager the {@link AuthorizationManager} to use
		 * @return the {@link Builder} for further customizations
		 */
		public B add(RequestMatcher matcher, AuthorizationManager<RequestAuthorizationContext> manager) {
			Assert.state(!this.anyRequestConfigured, "Can't add mappings after anyRequest");
			Assert.notNull(matcher, "matcher cannot be null");
			Assert.notNull(manager, "manager cannot be null");
			this.mappings.add(new RequestMatcherEntry<>(matcher, manager));
			return (B) this;
		}

		/**
		 * Allows to configure the {@link RequestMatcher} to {@link AuthorizationManager}
		 * mappings.
		 * @param mappingsConsumer used to configure the {@link RequestMatcher} to
		 * {@link AuthorizationManager} mappings.
		 * @return the {@link Builder} for further customizations
		 * @since 5.7
		 */
		public B mappings(
				Consumer<List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>>> mappingsConsumer) {
			Assert.state(!this.anyRequestConfigured, "Can't configure mappings after anyRequest");
			Assert.notNull(mappingsConsumer, "mappingsConsumer cannot be null");
			mappingsConsumer.accept(this.mappings);
			return (B) this;
		}

		/**
		 * Maps any request.
		 * @return the {@link AuthorizedUrl} for further customizations
		 * @since 6.2
		 */
		public AuthorizedUrl<B> anyRequest() {
			Assert.state(!this.anyRequestConfigured, "Can't configure anyRequest after itself");
			this.anyRequestConfigured = true;
			return new AuthorizedUrl<>(AnyRequestMatcher.INSTANCE);
		}

		/**
		 * Maps {@link RequestMatcher}s to {@link AuthorizationManager}.
		 * @param matchers the {@link RequestMatcher}s to map
		 * @return the {@link AuthorizedUrl} for further customizations
		 * @since 6.2
		 */
		public AuthorizedUrl<B> requestMatchers(RequestMatcher... matchers) {
			Assert.state(!this.anyRequestConfigured, "Can't configure requestMatchers after anyRequest");
			return new AuthorizedUrl<>(matchers);
		}

		/**
		 * Creates a {@link RequestMatcherDelegatingAuthorizationManager} instance.
		 * @return the {@link RequestMatcherDelegatingAuthorizationManager} instance
		 */
		public RequestMatcherDelegatingAuthorizationManager build() {
			return new RequestMatcherDelegatingAuthorizationManager(this.mappings);
		}

		/**
		 * An object that allows configuring the {@link AuthorizationManager} for
		 * {@link RequestMatcher}s.
		 *
		 * @author Evgeniy Cheban
		 * @since 6.2
		 */
		public final class AuthorizedUrl<B> {

			private final List<RequestMatcher> matchers;

			private AuthorizedUrl(RequestMatcher... matchers) {
				this(List.of(matchers));
			}

			private AuthorizedUrl(List<RequestMatcher> matchers) {
				this.matchers = matchers;
			}

			/**
			 * Specify that URLs are allowed by anyone.
			 * @return the {@link Builder} for further customizations
			 */
			public B permitAll() {
				return access((a, o) -> new AuthorizationDecision(true));
			}

			/**
			 * Specify that URLs are not allowed by anyone.
			 * @return the {@link Builder} for further customizations
			 */
			public B denyAll() {
				return access((a, o) -> new AuthorizationDecision(false));
			}

			/**
			 * Specify that URLs are allowed by any authenticated user.
			 * @return the {@link Builder} for further customizations
			 */
			public B authenticated() {
				return access(AuthenticatedAuthorizationManager.authenticated());
			}

			/**
			 * Specify that URLs are allowed by users who have authenticated and were not
			 * "remembered".
			 * @return the {@link Builder} for further customization
			 */
			public B fullyAuthenticated() {
				return access(AuthenticatedAuthorizationManager.fullyAuthenticated());
			}

			/**
			 * Specify that URLs are allowed by users that have been remembered.
			 * @return the {@link Builder} for further customization
			 */
			public B rememberMe() {
				return access(AuthenticatedAuthorizationManager.rememberMe());
			}

			/**
			 * Specify that URLs are allowed by anonymous users.
			 * @return the {@link Builder} for further customization
			 */
			public B anonymous() {
				return access(AuthenticatedAuthorizationManager.anonymous());
			}

			/**
			 * Specifies a user requires a role.
			 * @param role the role that should be required which is prepended with ROLE_
			 * automatically (i.e. USER, ADMIN, etc). It should not start with ROLE_
			 * @return {@link Builder} for further customizations
			 */
			public B hasRole(String role) {
				return access(AuthorityAuthorizationManager.hasRole(role));
			}

			/**
			 * Specifies that a user requires one of many roles.
			 * @param roles the roles that the user should have at least one of (i.e.
			 * ADMIN, USER, etc). Each role should not start with ROLE_ since it is
			 * automatically prepended already
			 * @return the {@link Builder} for further customizations
			 */
			public B hasAnyRole(String... roles) {
				return access(AuthorityAuthorizationManager.hasAnyRole(roles));
			}

			/**
			 * Specifies a user requires an authority.
			 * @param authority the authority that should be required
			 * @return the {@link Builder} for further customizations
			 */
			public B hasAuthority(String authority) {
				return access(AuthorityAuthorizationManager.hasAuthority(authority));
			}

			/**
			 * Specifies that a user requires one of many authorities.
			 * @param authorities the authorities that the user should have at least one
			 * of (i.e. ROLE_USER, ROLE_ADMIN, etc)
			 * @return the {@link Builder} for further customizations
			 */
			public B hasAnyAuthority(String... authorities) {
				return access(AuthorityAuthorizationManager.hasAnyAuthority(authorities));
			}

			private B access(AuthorizationManager<RequestAuthorizationContext> manager) {
				for (RequestMatcher matcher : this.matchers) {
					Builder.this.mappings.add(new RequestMatcherEntry<>(matcher, manager));
				}
				return (B) Builder.this;
			}

		}

	}

	public abstract static class ServletBuilder<SB extends ServletBuilder<SB>> extends Builder<ServletBuilder<SB>> {

		public abstract ServletBuilder<SB> rootServlet(Consumer<PathsBuilder> paths);

		public abstract ServletBuilder<SB> servletPath(String servletPath, Consumer<PathsBuilder> paths);

		public abstract class PathsBuilder {
			public abstract AuthorizedUrl<PathsBuilder> requestMatchers(HttpMethod method, String... path);
		}
	}

	final static class AntServletBuilder extends ServletBuilder<AntServletBuilder> {

		@Override
		public ServletBuilder<AntServletBuilder> rootServlet(Consumer<PathsBuilder> paths) {
			AntPathsBuilder builder = new AntPathsBuilder("");
			paths.accept(builder);
			return this;
		}

		@Override
		public ServletBuilder<AntServletBuilder> servletPath(String servletPath, Consumer<ServletBuilder<AntServletBuilder>.PathsBuilder> paths) {
			AntPathsBuilder builder = new AntPathsBuilder(servletPath);
			paths.accept(builder);
			return this;
		}

		class AntPathsBuilder extends PathsBuilder {
			private final String pathPrefix;

			AntPathsBuilder(String pathPrefix) {
				this.pathPrefix = pathPrefix;
			}

			@Override
			public AuthorizedUrl<PathsBuilder> requestMatchers(HttpMethod method, String... paths) {
				List<RequestMatcher> matchers = new ArrayList<>();
				for (String path : paths) {
					matchers.add(new AntPathRequestMatcher(this.pathPrefix + path));
				}
				return new AuthorizedUrl<PathsBuilder>(matchers);
			}
		}

	}

	final class MvcServletBuilder extends ServletBuilder<MvcServletBuilder> {

		private final HandlerMappingIntrospector introspector;

		MvcServletBuilder(HandlerMappingIntrospector introspector) {
			this.introspector = introspector;
		}

		@Override
		public ServletBuilder<MvcServletBuilder> rootServlet(Consumer<PathsBuilder> paths) {
			MvcPathsBuilder builder = new MvcPathsBuilder(this.introspector, null);
			paths.accept(builder);
			return this;
		}

		@Override
		public ServletBuilder<MvcServletBuilder> servletPath(String servletPath, Consumer<PathsBuilder> paths) {
			MvcPathsBuilder builder = new MvcPathsBuilder(this.introspector, servletPath);
			paths.accept(builder);
			return this;
		}

		class MvcPathsBuilder extends PathsBuilder {
			private final HandlerMappingIntrospector introspector;

			private final String pathPrefix;

			MvcPathsBuilder(HandlerMappingIntrospector introspector, String pathPrefix) {
				this.introspector = introspector;
				this.pathPrefix = pathPrefix;
			}

			@Override
			public AuthorizedUrl<PathsBuilder> requestMatchers(HttpMethod method, String... paths) {
				List<RequestMatcher> matchers = new ArrayList<>();
				for (String path : paths) {
					MvcRequestMatcher mvc = new MvcRequestMatcher(this.introspector, path);
					if (this.pathPrefix != null) {
						mvc.setServletPath(this.pathPrefix);
					}
					matchers.add(mvc);
				}
				return new AuthorizedUrl<PathsBuilder>(matchers);
			}
		}
	}

	final static class ServletSelectingServletBuilder extends ServletBuilder<ServletSelectingServletBuilder> {

		@Override
		public ServletBuilder<ServletSelectingServletBuilder> rootServlet(Consumer<PathsBuilder> paths) {
			return null;
		}

		@Override
		public ServletBuilder<ServletSelectingServletBuilder> servletPath(String servletPath, Consumer<PathsBuilder> paths) {
			return null;
		}

		class ServletSelectingPathsBuilder extends PathsBuilder {
			private final String pathPrefix;
			private final HandlerMappingIntrospector introspector;
			private final ServletContext servletContext;

			ServletSelectingPathsBuilder(AntServletBuilder.AntPathsBuilder ant, MvcServletBuilder.MvcPathsBuilder mvc, ServletContext servletContext) {

			}

			@Override
			public AuthorizedUrl<PathsBuilder> requestMatchers(HttpMethod method, String... paths) {
				List<RequestMatcher> matchers = new ArrayList<>();
				for (String path : paths) {
					AntPathRequestMatcher ant = new AntPathRequestMatcher(this.pathPrefix + path);
					MvcRequestMatcher mvc = new MvcRequestMatcher(this.introspector, path);
					if (this.pathPrefix != null) {
						mvc.setServletPath(this.pathPrefix);
					}
					matchers.add(new DeferredRequestMatcher((sc) -> resolve(ant, mvc, servletContext), mvc, ant));
				}
				return new AuthorizedUrl<PathsBuilder>(matchers);
			}

			private RequestMatcher resolve(AntPathRequestMatcher ant, MvcRequestMatcher mvc, ServletContext servletContext) {
				Map<String, ? extends ServletRegistration> registrations = mappableServletRegistrations(servletContext);
				if (registrations.isEmpty()) {
					return new DispatcherServletDelegatingRequestMatcher(ant, mvc, new MockMvcRequestMatcher());
				}
				if (!hasDispatcherServlet(registrations)) {
					return new DispatcherServletDelegatingRequestMatcher(ant, mvc, new MockMvcRequestMatcher());
				}
				ServletRegistration dispatcherServlet = requireOneRootDispatcherServlet(registrations);
				if (dispatcherServlet != null) {
					if (registrations.size() == 1) {
						return mvc;
					}
					return new DispatcherServletDelegatingRequestMatcher(ant, mvc, servletContext);
				}
				dispatcherServlet = requireOnlyPathMappedDispatcherServlet(registrations);
				if (dispatcherServlet != null) {
					String mapping = dispatcherServlet.getMappings().iterator().next();
					mvc.setServletPath(mapping.substring(0, mapping.length() - 2));
					return mvc;
				}
				return new DispatcherServletDelegatingRequestMatcher(ant, mvc, servletContext);
			}

			static class DeferredRequestMatcher implements RequestMatcher {

				final Function<ServletContext, RequestMatcher> requestMatcherFactory;

				final AtomicReference<String> description = new AtomicReference<>();

				final Map<ServletContext, RequestMatcher> requestMatchers = new ConcurrentHashMap<>();

				DeferredRequestMatcher(Function<ServletContext, RequestMatcher> resolver, RequestMatcher... candidates) {
					this.requestMatcherFactory = (sc) -> this.requestMatchers.computeIfAbsent(sc, resolver);
					this.description.set("Deferred " + Arrays.toString(candidates));
				}

				RequestMatcher requestMatcher(ServletContext servletContext) {
					return this.requestMatcherFactory.apply(servletContext);
				}

				@Override
				public boolean matches(HttpServletRequest request) {
					return this.requestMatcherFactory.apply(request.getServletContext()).matches(request);
				}

				@Override
				public MatchResult matcher(HttpServletRequest request) {
					return this.requestMatcherFactory.apply(request.getServletContext()).matcher(request);
				}

				@Override
				public String toString() {
					return this.description.get();
				}

			}
		}
	}

	static class MockMvcRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			return request.getAttribute("org.springframework.test.web.servlet.MockMvc.MVC_RESULT_ATTRIBUTE") != null;
		}

	}

	static class DispatcherServletRequestMatcher implements RequestMatcher {

		private final ServletContext servletContext;

		DispatcherServletRequestMatcher(ServletContext servletContext) {
			this.servletContext = servletContext;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			String name = request.getHttpServletMapping().getServletName();
			ServletRegistration registration = this.servletContext.getServletRegistration(name);
			Assert.notNull(registration,
					() -> computeErrorMessage(this.servletContext.getServletRegistrations().values()));
			try {
				Class<?> clazz = Class.forName(registration.getClassName());
				return DispatcherServlet.class.isAssignableFrom(clazz);
			}
			catch (ClassNotFoundException ex) {
				return false;
			}
		}

	}

	static class DispatcherServletDelegatingRequestMatcher implements RequestMatcher {

		private final AntPathRequestMatcher ant;

		private final MvcRequestMatcher mvc;

		private final RequestMatcher dispatcherServlet;

		DispatcherServletDelegatingRequestMatcher(AntPathRequestMatcher ant, MvcRequestMatcher mvc,
				ServletContext servletContext) {
			this(ant, mvc, new OrRequestMatcher(new MockMvcRequestMatcher(),
					new DispatcherServletRequestMatcher(servletContext)));
		}

		DispatcherServletDelegatingRequestMatcher(AntPathRequestMatcher ant, MvcRequestMatcher mvc,
				RequestMatcher dispatcherServlet) {
			this.ant = ant;
			this.mvc = mvc;
			this.dispatcherServlet = dispatcherServlet;
		}

		RequestMatcher requestMatcher(HttpServletRequest request) {
			if (this.dispatcherServlet.matches(request)) {
				return this.mvc;
			}
			return this.ant;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return requestMatcher(request).matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			return requestMatcher(request).matcher(request);
		}

		@Override
		public String toString() {
			return "DispatcherServletDelegating [" + "ant = " + this.ant + ", mvc = " + this.mvc + "]";
		}

	}

}
