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

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
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
 * However, it's best to use this class explicitly, declaring what kind of endpoint each
 * one is, like so: <code>
 *  ServletRequestMatcherBuilder builder = new ServletRequestMatcherBuilder(applicationContext);
 * 	http
 *		.authorizeHttpRequests((authorize) -> authorize
 *	        .requestMatchers(builder.mvc().matchers("/js/**", "/css/**")).permitAll()
 *	        .requestMatchers(builder.mvc().matchers("/my/controller/**")).hasAuthority("CONTROLLER")
 *	        .requestMatchers(builder.servletPath("/h2-console").matchers(/**")).hasAuthority("H2")
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

	private final Collection<ServletRegistration> registrations;

	public ServletRequestMatcherBuilder(ApplicationContext context) {
		this.context = context;
		this.registrations = ServletRegistrationUtils.registrations(this.context);
		this.delegate = delegate(this.context, this.registrations);
	}

	private static AbstractRequestMatcherBuilder delegate(ApplicationContext context,
			Collection<ServletRegistration> registrations) {
		if (!mvcPresent || context == null) {
			return AntPathRequestMatcherBuilder.absolute();
		}
		if (registrations.isEmpty()) {
			return MvcRequestMatcherBuilder.absolute(context);
		}
		Collection<ServletRegistration> dispatcherServlets = ServletRegistrationUtils.dispatcherServlets(registrations);
		if (dispatcherServlets.isEmpty()) {
			return AntPathRequestMatcherBuilder.absolute();
		}
		ServletRegistrationUtils.ServletPath servletPath = ServletRegistrationUtils.deduceServletPath(registrations);
		if (servletPath != null) {
			return MvcRequestMatcherBuilder.relativeTo(context, servletPath.path());
		}
		servletPath = ServletRegistrationUtils.deduceServletPath(dispatcherServlets);
		if (servletPath == null) {
			return null;
		}
		logger.warn(message("""
				Your servlet configuration has multiple servlet mappings. As such, you should
				declare your authorization rules using a ServletRequestMatchersBuilder bean, specifying the
				servlet path in each pattern, as follows:

					http
						.authorizeHttpRequests((authorize) -> authorize
							.requestMatchers(builder.servletPath("/h2-console").matchers("/**")).hasAuthority(...)
							.requestMatchers(builder.mvc().matchers("/my/**", "/controllers/**")).hasAuthority(...)

				As an alternative, you can remove any unneeded servlets from your application.

				For your reference, the servlet paths in your configuration are as follows: %s
			""", registrations));
		return new ServletPathAwareRequestMatcherBuilder(
				MvcRequestMatcherBuilder.relativeTo(context, servletPath.path()),
				AntPathRequestMatcherBuilder.absolute());
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
		ServletRegistration registration = ServletRegistrationUtils.registrationByServletPath(this.registrations, "/");
		Assert.notNull(registration, () -> message("There appears to be no default servlet: %s", this.registrations));
		if (ServletRegistrationUtils.isDispatcherServlet(registration)) {
			return MvcRequestMatcherBuilder.absolute(this.context);
		}
		return AntPathRequestMatcherBuilder.absolute();
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
		ServletRegistration registration = ServletRegistrationUtils.registrationByServletPath(this.registrations, path);
		Assert.notNull(registration,
				() -> message("The given path doesn't seem to match any configured servlets: %s", this.registrations));
		if (ServletRegistrationUtils.isDispatcherServlet(registration)) {
			return MvcRequestMatcherBuilder.relativeTo(this.context, path);
		}
		return AntPathRequestMatcherBuilder.relativeTo(path);
	}

	/**
	 * Create a new {@link RequestMatcherBuilder} based off on Spring MVC's {@link DispatcherServlet}.
	 *
	 * <p>If no {@link DispatcherServlet} is found or if multiple are found, then an error is returned.
	 *
	 * <p>If your {@link DispatcherServlet} is deployed as the default servlet (this is the default behavior),
	 * then calling {@link #mvc} is equivalent to calling {@link #defaultServlet()}.
	 *
	 * <p>If your {@link DispatcherServlet} is deployed to `/path`, then calling {@link #mvc} is equivalent
	 * to calling {@code #servletPath("/path")}.
	 *
	 * @return a {@link RequestMatcherBuilder} for Spring MVC URIs
	 */
	public RequestMatcherBuilder mvc() {
		requireDelegate();
		if (this.delegate instanceof MvcRequestMatcherBuilder) {
			return this.delegate;
		}
		if (this.delegate instanceof ServletPathAwareRequestMatcherBuilder) {
			return ((ServletPathAwareRequestMatcherBuilder) this.delegate).mvc;
		}
		throw new IllegalArgumentException(message("""
				Your application does not appear to be configured for Spring MVC.

				For your reference, here is your servlet configuration: %s

				If you believe this is in error, please construct a MvcRequestMatcher manually instead.
			""", this.registrations));
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
		if (this.delegate == null) {
			String template = """
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
								.requestMatchers(builder.servletPath("/mvc-one").matchers("/controller/**", "/endpoints/**"))
								.requestMatchers(builder.servletPath("/mvc-two").matchers("/other/**", "/controllers/**"));

						return http.build();
					}
				""";
			throw new IllegalArgumentException(message(template, this.registrations));
		}
	}

	private static String message(String template, Collection<? extends ServletRegistration> registrations) {
		return String.format(template, ServletRegistrationUtils.mappingsByServletName(registrations));
	}

	static final class ServletPathAwareRequestMatcherBuilder extends AbstractRequestMatcherBuilder {

		final MvcRequestMatcherBuilder mvc;

		final AntPathRequestMatcherBuilder ant;

		ServletPathAwareRequestMatcherBuilder(MvcRequestMatcherBuilder mvc, AntPathRequestMatcherBuilder ant) {
			this.mvc = mvc;
			this.ant = ant;
		}

		@Override
		public RequestMatcher matcher(String pattern) {
			MvcRequestMatcher mvc = this.mvc.matcher(pattern);
			AntPathRequestMatcher ant = this.ant.matcher(pattern);
			return new ServletPathAwareRequestMatcher(mvc, ant);
		}

		@Override
		public RequestMatcher matcher(HttpMethod method, String pattern) {
			MvcRequestMatcher mvc = this.mvc.matcher(method, pattern);
			AntPathRequestMatcher ant = this.ant.matcher(method, pattern);
			return new ServletPathAwareRequestMatcher(mvc, ant);
		}

	}

	static final class ServletPathAwareRequestMatcher implements RequestMatcher {

		final MvcRequestMatcher mvc;

		final AntPathRequestMatcher ant;

		final Map<String, Boolean> isDispatcherServlet = new ConcurrentHashMap<>();

		ServletPathAwareRequestMatcher(MvcRequestMatcher mvc, AntPathRequestMatcher ant) {
			this.mvc = mvc;
			this.ant = ant;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			String servletName = request.getHttpServletMapping().getServletName();
			ServletRegistration registration = request.getServletContext().getServletRegistration(servletName);
			if (isDispatcherServlet(registration)) {
				return this.mvc.matches(request);
			}
			return this.ant.matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			String servletName = request.getHttpServletMapping().getServletName();
			ServletRegistration registration = request.getServletContext().getServletRegistration(servletName);
			if (isDispatcherServlet(registration)) {
				return this.mvc.matcher(request);
			}
			return this.ant.matcher(request);
		}

		private boolean isDispatcherServlet(ServletRegistration registration) {
			return this.isDispatcherServlet.computeIfAbsent(registration.getName(),
					(name) -> ServletRegistrationUtils.isDispatcherServlet(registration));
		}

	}

}
