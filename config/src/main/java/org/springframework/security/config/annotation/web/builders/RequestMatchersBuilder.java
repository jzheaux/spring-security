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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

public class RequestMatchersBuilder {

	private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

	private static final Log logger = LogFactory.getLog(RequestMatchersBuilder.class);

	private final ApplicationContext context;

	private final RequestMatcherBuilder builder;

	private final Collection<ServletRegistration> registrations;

	private final String servletPath;

	public RequestMatchersBuilder(ApplicationContext context) {
		this(context, null);
	}

	private RequestMatchersBuilder(ApplicationContext context, String servletPath) {
		this.context = context;
		this.registrations = registrations(context, servletPath);
		this.builder = requestMatcherBuilder(context, this.registrations, servletPath);
		this.servletPath = servletPath;
	}

	private static RequestMatcherBuilder requestMatcherBuilder(ApplicationContext context,
			Collection<ServletRegistration> registrations, String servletPath) {
		boolean hasIntrospector = context != null && context.containsBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME);
		if (!hasIntrospector) {
			return new AntPathRequestMatcherBuilder(servletPath);
		}
		if (registrations == null || registrations.isEmpty()) {
			return new MvcRequestMatcherBuilder(context, servletPath);
		}
		Collection<ServletRegistration> dispatcherServlets = dispatcherServlets(registrations);
		if (dispatcherServlets.isEmpty()) {
			return new AntPathRequestMatcherBuilder(servletPath);
		}
		if (registrations.size() == 1) {
			ServletRegistration registration = registrations.iterator().next();
			if (servletPath != null) {
				return new MvcRequestMatcherBuilder(context, servletPath);
			}
			Collection<String> mappings = registration.getMappings();
			if (mappings.size() != 1) {
				return null;
			}
			String mapping = mappings.iterator().next();
			if ("/".equals(mapping)) {
				return new MvcRequestMatcherBuilder(context, null);
			}
			return new MvcRequestMatcherBuilder(context, mapping);
		}
		if (dispatcherServlets.size() > 1) {
			return null;
		}
		Collection<String> mappings = dispatcherServlets.iterator().next().getMappings();
		if (mappings.size() != 1) {
			return null;
		}
		logger.warn(computeErrorMessage("Your configuration has multiple path-based servlets. As such, you should "
				+ "declare your authorization rules using a RequestMatchersBuilder bean, specifying the servlet path "
				+ "in each pattern, as follows: " + "\n" + "\n\thttp "
				+ "\n\t\t.authorizeHttpRequests((authorize) -> authorize"
				+ "\n\t\t\t.requestMatchers(requestMatchersBuilder.servletPath(\"/\").matchers(\"/my/**\", \"/endpoints/**\")).hasAuthority(...) "
				+ "\n\n" + "As an alternative, you can remove any unneeded servlets from your application. "
				+ "For your reference, your the servlet paths in your configuration are as follows: %s",
				registrations));
		return new ServletPathAwareRequestMatcherBuilder(
				new MvcRequestMatcherBuilder(context, mappings.iterator().next()),
				new AntPathRequestMatcherBuilder(null));
	}

	private static Collection<ServletRegistration> registrations(ApplicationContext context, String servletPath) {
		if (!(context instanceof WebApplicationContext web)) {
			return Collections.emptyList();
		}
		ServletContext servletContext = web.getServletContext();
		if (servletContext == null) {
			return Collections.emptyList();
		}
		Map<String, ? extends ServletRegistration> registrations = servletContext.getServletRegistrations();
		if (registrations == null) {
			return Collections.emptyList();
		}
		Collection<ServletRegistration> filtered = new ArrayList<>();
		for (ServletRegistration registration : registrations.values()) {
			Collection<String> mappings = registration.getMappings();
			if (CollectionUtils.isEmpty(mappings)) {
				continue;
			}
			if (servletPath == null) {
				filtered.add(registration);
			}
			else if (mappings.contains(servletPath) || mappings.contains(servletPath + "/*")) {
				filtered.add(registration);
			}
		}
		if (servletPath == null) {
			return filtered;
		}
		if (filtered.isEmpty()) {
			throw new IllegalArgumentException(computeErrorMessage(
					"The servlet path you specified does not seem to match any " + "configured servlets: %s",
					registrations.values()));
		}
		return filtered;
	}

	private static Collection<ServletRegistration> dispatcherServlets(Collection<ServletRegistration> registrations) {
		Class<?> dispatcherServlet = ClassUtils.resolveClassName("org.springframework.web.servlet.DispatcherServlet",
				null);
		Collection<ServletRegistration> dispatcherServlets = new ArrayList<>();
		for (ServletRegistration registration : registrations) {
			try {
				Class<?> clazz = Class.forName(registration.getClassName());
				if (dispatcherServlet.isAssignableFrom(clazz)) {
					dispatcherServlets.add(registration);
				}
			}
			catch (ClassNotFoundException ignored) {
				// ignore
			}
		}
		return dispatcherServlets;
	}

	private static String computeErrorMessage(String template,
			Collection<? extends ServletRegistration> registrations) {
		Map<String, Collection<String>> mappings = new LinkedHashMap<>();
		for (ServletRegistration registration : registrations) {
			mappings.put(registration.getClassName(), registration.getMappings());
		}
		return String.format(template, mappings);
	}

	public RequestMatcher matcher() {
		Assert.notNull(this.servletPath, "To use `#matcher`, you must also specify a servlet path");
		return new AntPathRequestMatcher(this.servletPath);
	}

	public RequestMatcher[] matchers(HttpMethod method, String... patterns) {
		checkServletPath();
		RequestMatcher[] matchers = new RequestMatcher[patterns.length];
		for (int index = 0; index < patterns.length; index++) {
			matchers[index] = this.builder.matcher(method, patterns[index]);
		}
		return matchers;
	}

	public RequestMatcher[] matchers(String... patterns) {
		checkServletPath();
		RequestMatcher[] matchers = new RequestMatcher[patterns.length];
		for (int index = 0; index < patterns.length; index++) {
			matchers[index] = this.builder.matcher(patterns[index]);
		}
		return matchers;
	}

	public RequestMatchersBuilder mvc() {
		Collection<ServletRegistration> dispatcherServlets = dispatcherServlets(this.registrations);
		if (dispatcherServlets.isEmpty()) {
			throw new IllegalArgumentException(
					"Spring MVC does not appear to be configured for this application; please either configure Spring MVC or use `#servletPath` instead.");
		}
		if (dispatcherServlets.size() > 1) {
			throw new IllegalArgumentException(
					"There appears to be more than one dispatcher servlet configured. As such, you will need to use `#servletPath` instead in order to specify which path these matchers are for.");
		}
		if (dispatcherServlets.iterator().next().getMappings().size() > 1) {
			throw new IllegalArgumentException(
					"There apppears to be more than one mapping for this dispatcher servlet. As such, you will need to use `#servletPath` instead in order to specify which path these matchers are for.");
		}
		return servletPath(dispatcherServlets.iterator().next().getMappings().iterator().next());
	}

	public RequestMatchersBuilder servletPath(String path) {
		return new RequestMatchersBuilder(this.context, path);
	}

	private void checkServletPath() {
		if (this.builder == null) {
			String template = "This method cannot decide whether these patterns are Spring MVC patterns or not. "
					+ "You will need to specify the servlet path for each endpoint to assist with disambiguation. "
					+ "\n\nFor your reference, these are the servlets that have potentially ambiguous paths: %s"
					+ "\n\nTo do this, you can use the RequestMatchersBuilder bean in conjunction with requestMatchers like so: "
					+ "\n\n\thttp" + "\n\t\t.authorizeHttpRequests((authorize) -> authorize"
					+ "\n\t\t\t.requestMatchers(builder.servletPath(\"/\").matchers(\"/my\", \"/controller\", \"endpoints\")).";
			throw new IllegalArgumentException(computeErrorMessage(template, this.registrations));
		}
	}

	private interface RequestMatcherBuilder {

		RequestMatcher matcher(String pattern);

		RequestMatcher matcher(HttpMethod method, String pattern);

	}

	private static final class MvcRequestMatcherBuilder implements RequestMatcherBuilder {

		private final HandlerMappingIntrospector introspector;

		private final String servletPath;

		private MvcRequestMatcherBuilder(ApplicationContext context, String servletPath) {
			this.introspector = context.getBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME,
					HandlerMappingIntrospector.class);
			if (servletPath != null && servletPath.endsWith("/*")) {
				this.servletPath = servletPath.substring(0, servletPath.length() - 2);
			}
			else {
				this.servletPath = servletPath;
			}
		}

		@Override
		public MvcRequestMatcher matcher(String pattern) {
			MvcRequestMatcher matcher = new MvcRequestMatcher(this.introspector, pattern);
			if (this.servletPath != null) {
				matcher.setServletPath(this.servletPath);
			}
			return matcher;
		}

		@Override
		public MvcRequestMatcher matcher(HttpMethod method, String pattern) {
			MvcRequestMatcher matcher = new MvcRequestMatcher(this.introspector, pattern);
			matcher.setMethod(method);
			if (this.servletPath != null) {
				matcher.setServletPath(this.servletPath);
			}
			return matcher;
		}

	}

	private static final class AntPathRequestMatcherBuilder implements RequestMatcherBuilder {

		private final String servletPath;

		private AntPathRequestMatcherBuilder(String servletPath) {
			if (servletPath != null && servletPath.endsWith("/*")) {
				this.servletPath = servletPath.substring(0, servletPath.length() - 2);
			}
			else {
				this.servletPath = servletPath;
			}
		}

		@Override
		public AntPathRequestMatcher matcher(String pattern) {
			return matcher((String) null, pattern);
		}

		@Override
		public AntPathRequestMatcher matcher(HttpMethod method, String pattern) {
			return matcher((method != null) ? method.name() : null, pattern);
		}

		private AntPathRequestMatcher matcher(String method, String pattern) {
			return new AntPathRequestMatcher(prependServletPath(pattern), method);
		}

		private String prependServletPath(String pattern) {
			if (this.servletPath == null) {
				return pattern;
			}
			if (this.servletPath.startsWith("/") && this.servletPath.length() > 1) {
				return this.servletPath + pattern;
			}
			return pattern;
		}

	}

	private static final class ServletPathAwareRequestMatcherBuilder implements RequestMatcherBuilder {

		private final MvcRequestMatcherBuilder mvc;

		private final AntPathRequestMatcherBuilder ant;

		private ServletPathAwareRequestMatcherBuilder(MvcRequestMatcherBuilder mvc, AntPathRequestMatcherBuilder ant) {
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

		private static boolean isDispatcherServlet(ServletRegistration registration) {
			Class<?> dispatcherServlet = ClassUtils
					.resolveClassName("org.springframework.web.servlet.DispatcherServlet", null);
			try {
				Class<?> clazz = Class.forName(registration.getClassName());
				if (dispatcherServlet.isAssignableFrom(clazz)) {
					return true;
				}
			}
			catch (ClassNotFoundException ex) {
				return false;
			}
			return false;
		}

	}

}
