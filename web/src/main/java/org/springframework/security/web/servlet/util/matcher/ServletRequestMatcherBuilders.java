/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.servlet.util.matcher;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherBuilder;
import org.springframework.util.Assert;

/**
 * A {@link RequestMatcherBuilder} for specifying the servlet path separately from the
 * rest of the URI. This is helpful when you have more than one servlet.
 *
 * <p>
 * For example, if Spring MVC is deployed to `/mvc` and another servlet to `/other`, then
 * you can do
 * </p>
 *
 * <code>
 *     http
 *         .authorizeHttpRequests((authorize) -> authorize
 *         		.requestMatchers(servletPath("/mvc").pattern("/my/**", "/controller/**", "/endpoints/**")).hasAuthority(...
 *         		.requestMatchers(servletPath("/other").pattern("/my/**", "/non-mvc/**", "/endpoints/**")).hasAuthority(...
 *         	}
 *         	...
 * </code>
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class ServletRequestMatcherBuilders {

	private ServletRequestMatcherBuilders() {
	}

	/**
	 * Create {@link RequestMatcher}s that will only match URIs against the default
	 * servlet.
	 * @return a {@link ServletRequestMatcherBuilders} that matches URIs mapped to the
	 * default servlet
	 */
	public static RequestMatcherBuilder defaultServlet() {
		return servletPathInternal("");
	}

	/**
	 * Create {@link RequestMatcher}s that will only match URIs against the given servlet
	 * path
	 *
	 * <p>
	 * The path must be of the format {@code /path}. It should not end in `/` or `/*`, nor
	 * should it be a file extension. To specify the default servlet, use
	 * {@link #defaultServlet()}.
	 * </p>
	 * @return a {@link ServletRequestMatcherBuilders} that matches URIs mapped to the
	 * given servlet path
	 */
	public static RequestMatcherBuilder servletPath(String servletPath) {
		Assert.notNull(servletPath, "servletPath cannot be null");
		Assert.isTrue(servletPath.startsWith("/"), "servletPath must start with '/'");
		Assert.isTrue(!servletPath.endsWith("/"), "servletPath must not end with '/'");
		Assert.isTrue(!servletPath.endsWith("/*"), "servletPath must not end with '/*'");
		return servletPathInternal(servletPath);
	}

	private static RequestMatcherBuilder servletPathInternal(String servletPath) {
		PathPatternRequestMatcher.Builder builder = PathPatternRequestMatcher.builder();
		return (method, pattern) -> {
			Assert.notNull(pattern, "pattern cannot be null");
			Assert.isTrue(pattern.startsWith("/"), "pattern must start with '/'");
			return builder.pattern(method, servletPath + pattern);
		};
	}

}
