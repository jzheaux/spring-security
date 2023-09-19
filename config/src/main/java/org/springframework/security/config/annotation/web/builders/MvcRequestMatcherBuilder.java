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

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

public final class MvcRequestMatcherBuilder extends AbstractRequestMatcherBuilder {

	private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

	private final HandlerMappingIntrospector introspector;

	private final String servletPath;

	MvcRequestMatcherBuilder(ApplicationContext context, String servletPath) {
		this.introspector = context.getBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME, HandlerMappingIntrospector.class);
		// TODO ensure that only DEFAULT and PATH mappings are used
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
