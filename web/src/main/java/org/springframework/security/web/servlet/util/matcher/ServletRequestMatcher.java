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

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.MappingMatch;

import org.springframework.lang.Nullable;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.springframework.web.util.UriUtils;
import org.springframework.web.util.WebUtils;

/**
 * A {@link RequestMatcher} that ensures that the request's servlet information matches a
 * given criteria.
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class ServletRequestMatcher implements RequestMatcher {

	private static final String DEFAULT_SERVLET_PATH = "";

	private final String servletPath;

	ServletRequestMatcher(String servletPath) {
		this.servletPath = servletPath;
	}

	/**
	 * Create a {@link ServletRequestMatcher} that matches requests targeting the default
	 * servlet
	 * @return a {@link ServletRequestMatcher} matching the default servlet
	 */
	public static ServletRequestMatcher defaultServlet() {
		return new ServletRequestMatcher(DEFAULT_SERVLET_PATH);
	}

	/**
	 * Create a {@link ServletRequestMatcher} that matches requests targeting a given
	 * {@code servletPath}
	 *
	 * <p>
	 * Note that path should be supplied in the form {@code /path}, not {@code /path/*}
	 * </p>
	 * @return a {@link ServletRequestMatcher} matching a {@code servletPath}
	 */
	public static ServletRequestMatcher servletPath(String servletPath) {
		Assert.notNull(servletPath, "servletPath cannot be null");
		Assert.isTrue(servletPath.startsWith("/"), "servletPath must start with '/'");
		Assert.isTrue(!servletPath.endsWith("/"), "servletPath must not end with '/'");
		Assert.isTrue(!servletPath.endsWith("/*"), "servletPath must not end with '/*'");
		return new ServletRequestMatcher(servletPath);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean matches(HttpServletRequest request) {
		return this.servletPath.equals(pathPrefix(request));
	}

	String servletPath(HttpServletRequest request) {
		String servletPath = (String) request.getAttribute(WebUtils.INCLUDE_SERVLET_PATH_ATTRIBUTE);
		return (servletPath != null) ? servletPath : request.getServletPath();
	}

	@Nullable
	String pathPrefix(HttpServletRequest request) {
		HttpServletMapping mapping = (HttpServletMapping) request.getAttribute(RequestDispatcher.INCLUDE_MAPPING);
		mapping = (mapping != null) ? mapping : request.getHttpServletMapping();
		String servletPath = servletPath(request);
		if (ObjectUtils.nullSafeEquals(mapping.getMappingMatch(), MappingMatch.PATH)) {
			servletPath = (servletPath.endsWith("/") ? servletPath.substring(0, servletPath.length() - 1)
					: servletPath);
			return UriUtils.encodePath(servletPath, StandardCharsets.UTF_8);
		}
		return servletPath;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object o) {
		if (!(o instanceof ServletRequestMatcher that)) {
			return false;
		}
		return Objects.equals(this.servletPath, that.servletPath);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {
		return Objects.hashCode(this.servletPath);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		String servletPath = DEFAULT_SERVLET_PATH.equals(this.servletPath) ? "DEFAULT" : this.servletPath;
		return "ServletPathRequestMatcher [servletPath='" + servletPath + "']";
	}

}
