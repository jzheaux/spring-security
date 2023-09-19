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

import jakarta.servlet.ServletRegistration;

import org.springframework.util.ClassUtils;

final class ServletRegistrationUtils {

	private ServletRegistrationUtils() {

	}

	static ServletRegistration findRegistrationByMapping(Collection<ServletRegistration> registrations, String target) {
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

}
