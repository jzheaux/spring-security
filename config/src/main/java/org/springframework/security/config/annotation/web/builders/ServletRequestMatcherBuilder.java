/*
 * Copyright 2012-2023 the original author or authors.
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

package org.springframework.security.config.annotation.web.builders;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.builders.ServletRegistrationCollection.Registration;
import org.springframework.security.config.annotation.web.builders.ServletRegistrationCollection.ServletPath;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.web.servlet.DispatcherServlet;

/**
 * A {@link RequestMatcherBuilder} implementation that returns {@link RequestMatcher}
 * instances based on the type of servlet. If the servlet is
 * {@link org.springframework.web.servlet.DispatcherServlet}, then it will return
 * {@link MvcRequestMatcher}s; otherwise, it will return {@link AntPathRequestMatcher}s.
 *
 * <p>
 * Note that in many cases, which kind of request matcher is needed is apparent by the
 * servlet configuration.
 *
 * <p>
 * In all cases, you can indicate the servlet path by using the {@link #servletPath}
 * method.
 *
 * <p>
 * Consider, for example, the circumstance where you have Spring MVC configured and also
 * Spring Boot H2 Console. Spring MVC registers a servlet of type
 * {@link DispatcherServlet} as the default servlet and Spring Boot registers a servlet of
 * its own as well at `/h2-console/*`.
 *
 * <p>
 * Such might have a configuration like this in Spring Security: <code>
 * 	http
 *		.authorizeHttpRequests((authorize) -> authorize
 *	        .requestMatchers("/js/**", "/css/**").permitAll()
 *	        .requestMatchers("/my/controller/**").hasAuthority("CONTROLLER")
 *	        .requestMatchers("/h2-console/**").hasAuthority("H2")
 *	        .anyRequest().authenticated()
 *	    )
 *	    // ...
 * </code>
 *
 * <p>
 * This class will correctly assign {@link AntPathRequestMatcher}s to `h2-console`
 * endpoints and {@link MvcRequestMatcher} since this class is used by default in
 * {@link org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer}.
 *
 * <p>
 * Where this class is handy is that you can use it to declare all your paths in absolute
 * terms, including Spring MVC endpoints. For example, if you have Spring MVC and Spring
 * Boot's H2 Console both deployed, then you can do: <code>
 *  ServletRequestMatcherBuilder builder = new ServletRequestMatcherBuilder(applicationContext);
 * 	http
 *		.authorizeHttpRequests((authorize) -> authorize
 * 			.requestMatchers(builder.mvc().matchers("/js/**", "/css/**")).permitAll()
 *	        .requestMatchers(builder.mvc().matchers("/my/controller/**")).hasAuthority("CONTROLLER")
 *	        .requestMatchers(builder.servletPath("/h2-console").matchers("/**")).hasAuthority("OTHER")
 *	        .anyRequest().authenticated()
 *	    )
 *	    // ...
 * </code>
 *
 * <p>
 * While otherwise optional, this is necessary when there is more than one
 * {@link DispatcherServlet} mapping in your servlet configuration. If you have one
 * {@link DispatcherServlet} as the default servlet and one as mapping to `/mvc/*`, for
 * example, then you would do something like the following: <code>
 *  ServletRequestMatcherBuilder builder = new ServletRequestMatcherBuilder(applicationContext);
 * 	http
 *		.authorizeHttpRequests((authorize) -> authorize
 *	        .requestMatchers(builder.mvc().matchers("/js/**", "/css/**")).permitAll()
 *	        .requestMatchers(builder.mvc().matchers("/my/controller/**")).hasAuthority("CONTROLLER")
 *	        .requestMatchers(builder.mvc("/mvc").matchers("/my/others/**")).hasAuthority("OTHER")
 *	        .anyRequest().authenticated()
 *	    )
 *	    // ...
 * </code>
 *
 * @author Josh Cummings
 * @since 6.2
 * @see AbstractRequestMatcherRegistry
 */
public final class ServletRequestMatcherBuilder extends AbstractRequestMatcherBuilder {

	private static final String HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector";

	private static final boolean mvcPresent;

	static {
		mvcPresent = ClassUtils.isPresent(HANDLER_MAPPING_INTROSPECTOR,
				AbstractRequestMatcherRegistry.class.getClassLoader());
	}

	private static final Log logger = LogFactory.getLog(ServletRequestMatcherBuilder.class);

	private final ApplicationContext context;

	private final AbstractRequestMatcherBuilder delegate;

	private final ServletRegistrationCollection registrations;

	public ServletRequestMatcherBuilder(ApplicationContext context) {
		this.context = context;
		this.registrations = ServletRegistrationCollection.registrations(this.context);
		this.delegate = delegate(this.context, this.registrations);
	}

	private static AbstractRequestMatcherBuilder delegate(ApplicationContext context,
			ServletRegistrationCollection registrations) {
		if (!mvcPresent) {
			logger.trace("Defaulting to Ant matching since Spring MVC is not on the classpath");
			return AntPathRequestMatcherBuilder.absolute();
		}
		if (registrations.isEmpty()) {
			logger.trace(
					"Defaulting to MVC matching since Spring MVC is on the class path and no servlet information is available");
			return MvcRequestMatcherBuilder.absolute(context);
		}
		ServletRegistrationCollection dispatcherServlets = registrations.dispatcherServlets();
		if (dispatcherServlets.isEmpty()) {
			logger.trace("Defaulting to MVC matching since there is no DispatcherServlet configured");
			return AntPathRequestMatcherBuilder.absolute();
		}
		ServletPath servletPath = registrations.onlyServletPath();
		if (servletPath != null) {
			logger.trace(
					String.format("Defaulting to MVC matching since DispatcherServlet [%s] is the only servlet mapping",
							servletPath.path()));
			return MvcRequestMatcherBuilder.relativeTo(context, servletPath.path());
		}
		servletPath = dispatcherServlets.onlyServletPath();
		if (servletPath == null) {
			logger.trace("Did not choose a default since there is more than one DispatcherServlet mapping");
			return null;
		}
		logger.trace(
				"Defaulting to request-time checker since there is only one DispatcherServlet mapping, but also other servlet mappings");
		return new ServletPathDelegatingRequestMatcherBuilder(
				MvcRequestMatcherBuilder.relativeTo(context, servletPath.path()),
				AntPathRequestMatcherBuilder.absolute(), registrations);
	}

	/**
	 * Create a new {@link RequestMatcherBuilder} based off on the type of the default
	 * servlet.
	 *
	 * <p>
	 * If the default servlet is of type {@link DispatcherServlet}, then return a builder
	 * that builds {@link MvcRequestMatcher}s.
	 *
	 * <p>
	 * Otherwise, return a builder that builders {@link AntPathRequestMatcher}s.
	 * @return a {@link RequestMatcherBuilder} for URIs mapped to the default servlet
	 */
	public RequestMatcherBuilder defaultServlet() {
		Registration registration = this.registrations.registrationByServletPath("/");
		Assert.notNull(registration,
				() -> String.format("There appears to be no default servlet: %s", this.registrations));
		if (registration.isDispatcherServlet()) {
			return MvcRequestMatcherBuilder.absolute(this.context);
		}
		return AntPathRequestMatcherBuilder.absolute();
	}

	/**
	 * Create a new {@link RequestMatcherBuilder} based on Spring MVC's
	 * {@link DispatcherServlet} as the default servlet.
	 *
	 * <p>
	 * If no {@link DispatcherServlet} is found as the default servlet, then an error is
	 * returned.
	 *
	 * <p>
	 * If your {@link DispatcherServlet} is mapped as the default servlet (this is the
	 * default behavior), then calling {@link #mvc} is equivalent to calling
	 * {@link #defaultServlet()}.
	 *
	 * <p>
	 * If your {@link DispatcherServlet} is deployed to `/path`, call {@link #mvc(String)}
	 * instead.
	 * @return a {@link RequestMatcherBuilder} for Spring MVC URIs
	 */
	public RequestMatcherBuilder mvc() {
		RequestMatcherBuilder target = defaultServlet();
		Assert.isInstanceOf(MvcRequestMatcherBuilder.class, target, () -> String.format("In your configuration [%s], "
				+ "Spring MVC's DispatcherServlet is not mapped to `/`. If DispatcherServlet is mapped to another path "
				+ "then call `mvc(servletPath)`. Or if `/` maps to something other than DispatcherServlet, then call "
				+ "`defaultServlet()`", this.registrations));
		return target;
	}

	/**
	 * Create a new {@link RequestMatcherBuilder} based off on the type of the servlet
	 * mapped to the given path.
	 *
	 * <p>
	 * If the found servlet is of type {@link DispatcherServlet}, then return a builder
	 * that builds {@link MvcRequestMatcher}s.
	 *
	 * <p>
	 * Otherwise, return a builder that builders {@link AntPathRequestMatcher}s.
	 *
	 * <p>
	 * For example, if you have a servlet mapped to `/path/*` in your servlet
	 * configuration, then you can invoke `servletPath("/path")` to look up that servlet,
	 * inspect its type, and return the appropriate {@link RequestMatcherBuilder}.
	 * @param path the servlet path for the URI being tested
	 * @return a {@link RequestMatcherBuilder} for URIs mapped to the indicated servlet
	 */
	public RequestMatcherBuilder servletPath(String path) {
		Assert.notNull(path, "path cannot be null");
		Assert.isTrue(!"/".equals(path), "Please ensure your path starts with a `/`; "
				+ "if you are declaring a value for the default servlet, call `defaultServlet()` instead.");
		Assert.isTrue(!path.endsWith("/*"), "Please do not end your servlet path with `/*`; "
				+ "if you are mapping to a path-based servlet like `/path/*`, then pass `/path` to this method");
		Registration registration = this.registrations.registrationByServletPath(path);
		Assert.notNull(registration, () -> String
				.format("The given path doesn't seem to match any configured servlets: %s", this.registrations));
		if (registration.isDispatcherServlet()) {
			return MvcRequestMatcherBuilder.relativeTo(this.context, path);
		}
		return AntPathRequestMatcherBuilder.relativeTo(path);
	}

	/**
	 * Create a new {@link RequestMatcherBuilder} based on the {@link DispatcherServlet}
	 * mapped to the given path.
	 *
	 * <p>
	 * If no {@link DispatcherServlet} is found at the provided mapping, then an error is
	 * returned.
	 *
	 * <p>
	 * If your {@link DispatcherServlet} is mapped to `/path/*`, then calling
	 * {@code mvc("/path")} is equivalent to calling {@code servletPath("/path")}.
	 *
	 * <p>
	 * If your {@link DispatcherServlet} is mapped to the default servlet (the default
	 * behavior), call {@link #mvc} instead.
	 * @param servletPath the servlet path for the URI being tested
	 * @return @return a {@link RequestMatcherBuilder} for Spring MVC URIs mapped to the
	 * given servlet {@code path}
	 */
	public RequestMatcherBuilder mvc(String servletPath) {
		RequestMatcherBuilder target = servletPath(servletPath);
		Assert.isInstanceOf(MvcRequestMatcherBuilder.class, target, () -> String.format("In your configuration %s, "
				+ "Spring MVC's DispatcherServlet is not mapped to %s. If DispatcherServlet is mapped to `/`, "
				+ "then call `mvc()`. Or if this path maps to something other than DispatcherServlet, then call "
				+ "`servletPath(path)`", this.registrations, servletPath));
		return target;
	}

	@Override
	RequestMatcher matcher(HttpMethod method, String pattern) {
		requireDelegate();
		return this.delegate.matcher(method, pattern);
	}

	@Override
	RequestMatcher matcher(String pattern) {
		requireDelegate();
		return this.delegate.matcher(pattern);
	}

	private void requireDelegate() {
		Assert.notNull(this.delegate, () -> String.format("""
				This method cannot decide whether these patterns are Spring MVC patterns or not
				since your servlet configuration has multiple Spring MVC servlet mappings.

				For your reference, here is your servlet configuration: %s

				To address this, you need to specify the servlet path for each endpoint.
				You can use the ServletRequestMatchersBuilder bean in conjunction with requestMatchers do to this
				like so:

				@Bean
				SecurityFilterChain appSecurity(HttpSecurity http, ServletRequestMatcherBuilder builder) throws Exception {
					http
						.authorizeHttpRequests((authorize) -> authorize
							.requestMatchers(builder.mvc("/mvc-one").matchers("/controller/**", "/endpoints/**"))...
							.requestMatchers(builder.mvc("/mvc-two").matchers("/other/**", "/controllers/**"))...
							.requestMatchers(builder.servletPath("/h2-console").matchers("/**"))...;

					return http.build();
				}
				""", this.registrations));
	}

	static final class ServletPathDelegatingRequestMatcherBuilder extends AbstractRequestMatcherBuilder {

		final MvcRequestMatcherBuilder mvc;

		final AntPathRequestMatcherBuilder ant;

		final ServletRegistrationCollection registrations;

		ServletPathDelegatingRequestMatcherBuilder(MvcRequestMatcherBuilder mvc, AntPathRequestMatcherBuilder ant,
				ServletRegistrationCollection registrations) {
			this.mvc = mvc;
			this.ant = ant;
			this.registrations = registrations;
		}

		@Override
		public RequestMatcher matcher(String pattern) {
			MvcRequestMatcher mvc = this.mvc.matcher(pattern);
			AntPathRequestMatcher ant = this.ant.matcher(pattern);
			return new ServletPathDelegatingRequestMatcher(mvc, ant, this.registrations);
		}

		@Override
		public RequestMatcher matcher(HttpMethod method, String pattern) {
			MvcRequestMatcher mvc = this.mvc.matcher(method, pattern);
			AntPathRequestMatcher ant = this.ant.matcher(method, pattern);
			return new ServletPathDelegatingRequestMatcher(mvc, ant, this.registrations);
		}

	}

	static final class ServletPathDelegatingRequestMatcher implements RequestMatcher {

		final MvcRequestMatcher mvc;

		final AntPathRequestMatcher ant;

		final ServletRegistrationCollection registrations;

		ServletPathDelegatingRequestMatcher(MvcRequestMatcher mvc, AntPathRequestMatcher ant,
				ServletRegistrationCollection registrations) {
			this.mvc = mvc;
			this.ant = ant;
			this.registrations = registrations;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			String name = request.getHttpServletMapping().getServletName();
			Registration registration = this.registrations.registrationByName(name);
			Assert.notNull(registration,
					String.format("Could not find %s in servlet configuration %s", name, this.registrations));
			if (registration.isDispatcherServlet()) {
				return this.mvc.matches(request);
			}
			return this.ant.matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			String name = request.getHttpServletMapping().getServletName();
			Registration registration = this.registrations.registrationByName(name);
			Assert.notNull(registration,
					String.format("Could not find %s in servlet configuration %s", name, this.registrations));
			if (registration.isDispatcherServlet()) {
				return this.mvc.matcher(request);
			}
			return this.ant.matcher(request);
		}

	}

}
