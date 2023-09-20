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
import org.springframework.util.ClassUtils;

public class ServletRequestMatcherBuilder extends AbstractRequestMatcherBuilder {

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
		this.registrations = ServletRegistrationUtils.registrations(context);
		this.delegate = delegate(context, this.registrations);
	}

	private static AbstractRequestMatcherBuilder delegate(ApplicationContext context,
			Collection<ServletRegistration> registrations) {
		if (!mvcPresent || context == null) {
			return new AntPathRequestMatcherBuilder(null);
		}
		if (registrations.isEmpty()) {
			return new MvcRequestMatcherBuilder(context, null);
		}
		Collection<ServletRegistration> dispatcherServlets = ServletRegistrationUtils.dispatcherServlets(registrations);
		if (dispatcherServlets.isEmpty()) {
			return new AntPathRequestMatcherBuilder(null);
		}
		ServletRegistrationUtils.ServletPath servletPath = ServletRegistrationUtils.deduceServletPath(registrations);
		if (servletPath != null) {
			return new MvcRequestMatcherBuilder(context, servletPath.path());
		}
		servletPath = ServletRegistrationUtils.deduceServletPath(dispatcherServlets);
		if (servletPath == null) {
			return null;
		}
		logger.warn(computeErrorMessage("""
				Your servlet configuration has multiple path-based mappings. As such, you should
				declare your authorization rules using a RequestMatchersBuilder bean, specifying the servlet path
				in each pattern, as follows:

					http
						.authorizeHttpRequests((authorize) -> authorize
							.requestMatchers(builder.servletPath("/").matchers("/my/**", "/endpoints/**")).hasAuthority(...)

				As an alternative, you can remove any unneeded servlets from your application.

				For your reference, your the servlet paths in your configuration are as follows: %s
			""", registrations));
		return new ServletPathAwareRequestMatcherBuilder(
				new MvcRequestMatcherBuilder(context, servletPath.path()),
				new AntPathRequestMatcherBuilder(null));
	}

	public RequestMatcherBuilder mvc() {
		requireDelegate();
		if (this.delegate instanceof MvcRequestMatcherBuilder) {
			return this.delegate;
		}
		if (this.delegate instanceof ServletPathAwareRequestMatcherBuilder) {
			return ((ServletPathAwareRequestMatcherBuilder) this.delegate).mvc;
		}
		throw new IllegalArgumentException(computeErrorMessage("""
				Your application does not appear to be configured for Spring MVC.

				For your reference, here is your servlet configuration: %s

				If you believe this is in error, please construct a MvcRequestMatcher manually instead.
			""", this.registrations));
	}

	public RequestMatcherBuilder servletPath(String path) {
		if (!path.startsWith("/")) {
			throw new IllegalArgumentException(
					"Please ensure your servlet path starts with a /; if you are declaring a value for the default servlet, use `/`.");
		}
		if (path.endsWith("/*")) {
			throw new IllegalArgumentException(
					"Please do not end your servlet path with /*; if you are mapping to a path-based servlet like `/path/*`, then pass `/path` to this method");
		}
		ServletRegistration registration = ServletRegistrationUtils.findRegistrationByServletPath(this.registrations,
				path);
		if (registration == null) {
			throw new IllegalArgumentException(computeErrorMessage(
					"The servlet path you specified does not seem to match any configured servlets: %s",
					this.registrations));
		}
		if (ServletRegistrationUtils.isDispatcherServlet(registration)) {
			return new MvcRequestMatcherBuilder(this.context, ("/".equals(path)) ? null : path);
		}
		return new AntPathRequestMatcherBuilder(path);
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
					since your servlet configuration has multiple Spring MVC path-based mappings.

					For your reference, these are the servlets that have potentially ambiguous paths: %s

					To address this, you need to specify the servlet path for each endpoint.
					You can use the ServletRequestMatchersBuilder bean in conjunction with requestMatchers do to this
					like so:

					@Bean
					SecurityFilterChain appSecurity(HttpSecurity http, ServletRequestMatcherBuilder builder) throws Exception {
						http
							.authorizeHttpRequests((authorize) -> authorize
								.requestMatchers(builder.servletPath("/mvc-one").matchers("/controller/**", "/endpoints/**"))
								.requestMatchers(builder.servletPath("/mvc-two").anyRequest());

						return http.build();
					}
				""";
			throw new IllegalArgumentException(computeErrorMessage(template, this.registrations));
		}
	}

	private static String computeErrorMessage(String template,
			Collection<? extends ServletRegistration> registrations) {
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

		ServletPathAwareRequestMatcher(MvcRequestMatcher mvc, AntPathRequestMatcher ant) {
			this.mvc = mvc;
			this.ant = ant;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			String servletName = request.getHttpServletMapping().getServletName();
			ServletRegistration registration = request.getServletContext().getServletRegistration(servletName);
			if (ServletRegistrationUtils.isDispatcherServlet(registration)) {
				return this.mvc.matches(request);
			}
			return this.ant.matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			String servletName = request.getHttpServletMapping().getServletName();
			ServletRegistration registration = request.getServletContext().getServletRegistration(servletName);
			if (ServletRegistrationUtils.isDispatcherServlet(registration)) {
				return this.mvc.matcher(request);
			}
			return this.ant.matcher(request);
		}

	}

}
