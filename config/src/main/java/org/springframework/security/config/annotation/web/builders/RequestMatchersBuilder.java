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
		if (!hasDispatcherServlet(registrations)) {
			return new AntPathRequestMatcherBuilder(servletPath);
		}
		if (registrations.isEmpty()) {
			return new MvcRequestMatcherBuilder(context, servletPath);
		}
		if (registrations.size() == 1) {
			ServletRegistration registration = registrations.iterator().next();
			if (servletPath == null) {
				servletPath = deduceServletPath(registration);
			}
			return isDispatcherServlet(registration) ? new MvcRequestMatcherBuilder(context, servletPath)
					: new AntPathRequestMatcherBuilder(servletPath);
		}
		return null;
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
				for (String mapping : mappings) {
					if (mapping.equals("/") || mapping.endsWith("/*")) {
						filtered.add(registration);
						break;
					}
				}
				continue;
			}
			if (mappings.contains(servletPath) || mappings.contains(servletPath + "/*")) {
				filtered.add(registration);
			}
		}
		return filtered;
	}

	private static boolean hasDispatcherServlet(Collection<ServletRegistration> registrations) {
		for (ServletRegistration registration : registrations) {
			if (isDispatcherServlet(registration)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isDispatcherServlet(ServletRegistration registration) {
		Class<?> dispatcherServlet = ClassUtils.resolveClassName("org.springframework.web.servlet.DispatcherServlet",
				null);
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

	private static String deduceServletPath(ServletRegistration registration) {
		Collection<String> mappings = registration.getMappings();
		if (mappings.size() > 1) {
			return null;
		}
		String mapping = mappings.iterator().next();
		if (mapping.endsWith("/*")) {
			return mapping.substring(0, mapping.length() - 2);
		}
		return null;
	}

	public RequestMatcher matcher() {
		Assert.notNull(this.servletPath, computeErrorMessage());
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

	public RequestMatchersBuilder servletPath(String path) {
		return new RequestMatchersBuilder(this.context, path);
	}

	private void checkServletPath() {
		if (this.builder == null) {
			throw new IllegalArgumentException(computeErrorMessage());
		}
	}

	private String computeErrorMessage() {
		String template = "This method cannot decide whether these patterns are Spring MVC patterns or not. "
				+ "You will need to specify the servlet path for each endpoint to assist with disambiguation. "
				+ "\n\nFor your reference, these are the servlets that have potentially ambiguous paths: %s"
				+ "\n\nTo do this, you can use the RequestMatchersBuilder bean in conjunction with requestMatchers like so: "
				+ "\n\n\t.requestMatchers(builder.servletPath(\"/\").matchers(\"/my\", \"/controller\", \"endpoints\")).";
		Map<String, Collection<String>> mappings = new LinkedHashMap<>();
		for (ServletRegistration registration : this.registrations) {
			mappings.put(registration.getClassName(), registration.getMappings());
		}
		return String.format(template, mappings);
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
			this.servletPath = servletPath;
		}

		@Override
		public RequestMatcher matcher(String pattern) {
			MvcRequestMatcher matcher = new MvcRequestMatcher(this.introspector, pattern);
			if (this.servletPath != null) {
				matcher.setServletPath(this.servletPath);
			}
			return matcher;
		}

		@Override
		public RequestMatcher matcher(HttpMethod method, String pattern) {
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
			this.servletPath = servletPath;
		}

		@Override
		public RequestMatcher matcher(String pattern) {
			return matcher((String) null, pattern);
		}

		@Override
		public RequestMatcher matcher(HttpMethod method, String pattern) {
			return matcher((method != null) ? method.name() : null, pattern);
		}

		private RequestMatcher matcher(String method, String pattern) {
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

}
