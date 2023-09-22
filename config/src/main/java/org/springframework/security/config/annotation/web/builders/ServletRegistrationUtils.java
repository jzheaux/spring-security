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
import org.springframework.util.ClassUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.web.context.WebApplicationContext;

final class ServletRegistrationUtils {

	private ServletRegistrationUtils() {

	}

	static Collection<ServletRegistration> registrations(ApplicationContext context) {
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

	static ServletRegistration registrationByServletPath(Collection<ServletRegistration> registrations, String target) {
		for (ServletRegistration registration : registrations) {
			for (String mapping : registration.getMappings()) {
				if (target.equals(mapping) || (target + "/*").equals(mapping)) {
					return registration;
				}
			}
		}
		return null;
	}

	static Collection<ServletRegistration> dispatcherServlets(Collection<ServletRegistration> registrations) {
		Collection<ServletRegistration> dispatcherServlets = new ArrayList<>();
		for (ServletRegistration registration : registrations) {
			if (isDispatcherServlet(registration)) {
				dispatcherServlets.add(registration);
			}
		}
		return dispatcherServlets;
	}

	static boolean isDispatcherServlet(ServletRegistration registration) {
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

	static Map<String, Collection<String>> mappingsByServletName(
			Collection<? extends ServletRegistration> registrations) {
		Map<String, Collection<String>> mappings = new LinkedHashMap<>();
		for (ServletRegistration registration : registrations) {
			mappings.put(registration.getClassName(), registration.getMappings());
		}
		return mappings;
	}

	static ServletPath deduceServletPath(Collection<ServletRegistration> registrations) {
		if (registrations.size() > 1) {
			return null;
		}
		ServletRegistration registration = registrations.iterator().next();
		if (registration.getMappings().size() > 1) {
			return null;
		}
		String mapping = registration.getMappings().iterator().next();
		if ("/".equals(mapping)) {
			return new ServletPath();
		}
		if (mapping.endsWith("/*")) {
			return new ServletPath(mapping.substring(0, mapping.length() - 2));
		}
		return null;
	}

	record ServletPath(String path) {
		ServletPath() {
			this(null);
		}
	}

}
