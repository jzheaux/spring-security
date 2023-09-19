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
import org.springframework.util.CollectionUtils;
import org.springframework.web.context.WebApplicationContext;

public class ServletRequestMatcherBuilder extends AbstractRequestMatcherBuilder {

	private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

	private static final Log logger = LogFactory.getLog(ServletRequestMatcherBuilder.class);

	private final ApplicationContext context;

	private final AbstractRequestMatcherBuilder delegate;

	private final Collection<ServletRegistration> registrations;

	public ServletRequestMatcherBuilder(ApplicationContext context) {
		this.context = context;
		this.registrations = registrations(context);
		this.delegate = requestMatcherBuilder(context, this.registrations);
	}

	private static AbstractRequestMatcherBuilder requestMatcherBuilder(ApplicationContext context,
			Collection<ServletRegistration> registrations) {
		boolean hasIntrospector = context != null && context.containsBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME);
		if (!hasIntrospector) {
			return new AntPathRequestMatcherBuilder(null);
		}
		if (registrations == null || registrations.isEmpty()) {
			return new MvcRequestMatcherBuilder(context, null);
		}
		Collection<ServletRegistration> dispatcherServlets = ServletRegistrationUtils.dispatcherServlets(registrations);
		if (dispatcherServlets.isEmpty()) {
			return new AntPathRequestMatcherBuilder(null);
		}
		if (registrations.size() == 1) {
			ServletRegistration registration = registrations.iterator().next();
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

	private static Collection<ServletRegistration> registrations(ApplicationContext context) {
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
			if (!CollectionUtils.isEmpty(mappings)) {
				filtered.add(registration);
			}
		}
		return filtered;
	}

	private static String computeErrorMessage(String template,
			Collection<? extends ServletRegistration> registrations) {
		Map<String, Collection<String>> mappings = new LinkedHashMap<>();
		for (ServletRegistration registration : registrations) {
			mappings.put(registration.getClassName(), registration.getMappings());
		}
		return String.format(template, mappings);
	}

	@Override
	RequestMatcher matcher(HttpMethod method, String pattern) {
		checkServletPath();
		return this.delegate.matcher(method, pattern);
	}

	@Override
	RequestMatcher matcher(String pattern) {
		checkServletPath();
		return this.delegate.matcher(pattern);
	}

	public RequestMatcher servletPathMatcher(String path) {
		ServletRegistration registration = ServletRegistrationUtils.findRegistrationByMapping(this.registrations, path);
		if (registration == null) {
			throw new IllegalArgumentException(computeErrorMessage(
					"The servlet path you specified does not seem to match any " + "configured servlets: %s",
					this.registrations));
		}
		return new AntPathRequestMatcher(path);
	}

	public MvcRequestMatcherBuilder mvc() {
		Collection<ServletRegistration> dispatcherServlets = ServletRegistrationUtils
				.dispatcherServlets(this.registrations);
		if (dispatcherServlets.isEmpty()) {
			throw new IllegalArgumentException(
					"Spring MVC does not appear to be configured for this application; please either configure Spring MVC or use `#servletPath` instead.");
		}
		if (dispatcherServlets.size() > 1) {
			throw new IllegalArgumentException(
					"There appears to be more than one dispatcher servlet configured. As such, you will need to use `#servletPath` instead in order to specify which path these matchers are for.");
		}
		ServletRegistration registration = dispatcherServlets.iterator().next();
		if (registration.getMappings().size() > 1) {
			throw new IllegalArgumentException(
					"There appears to be more than one mapping for this dispatcher servlet. As such, you will need to use `#servletPath` instead in order to specify which path these matchers are for.");
		}
		return (MvcRequestMatcherBuilder) registration(registration, registration.getMappings().iterator().next());
	}

	public RequestMatcherBuilder servletPath(String path) {
		ServletRegistration registration = ServletRegistrationUtils.findRegistrationByMapping(this.registrations, path);
		if (registration == null) {
			throw new IllegalArgumentException(computeErrorMessage(
					"The servlet path you specified does not seem to match any " + "configured servlets: %s",
					this.registrations));
		}
		return registration(registration, path);
	}

	private RequestMatcherBuilder registration(ServletRegistration registration, String mapping) {
		if (ServletRegistrationUtils.isDispatcherServlet(registration)) {
			return new MvcRequestMatcherBuilder(this.context, mapping);
		}
		return new AntPathRequestMatcherBuilder(mapping);
	}

	private void checkServletPath() {
		if (this.delegate == null) {
			String template = "This method cannot decide whether these patterns are Spring MVC patterns or not. "
					+ "You will need to specify the servlet path for each endpoint to assist with disambiguation. "
					+ "\n\nFor your reference, these are the servlets that have potentially ambiguous paths: %s"
					+ "\n\nTo do this, you can use the RequestMatchersBuilder bean in conjunction with requestMatchers like so: "
					+ "\n\n\thttp" + "\n\t\t.authorizeHttpRequests((authorize) -> authorize"
					+ "\n\t\t\t.requestMatchers(builder.servletPath(\"/\").matchers(\"/my\", \"/controller\", \"endpoints\")).";
			throw new IllegalArgumentException(computeErrorMessage(template, this.registrations));
		}
	}

	static final class ServletPathAwareRequestMatcherBuilder extends AbstractRequestMatcherBuilder {

		private final MvcRequestMatcherBuilder mvc;

		private final AntPathRequestMatcherBuilder ant;

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
