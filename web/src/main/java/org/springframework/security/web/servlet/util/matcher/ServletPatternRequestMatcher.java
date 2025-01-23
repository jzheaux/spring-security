/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.Objects;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletMapping;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.lang.Nullable;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author Josh Cummings
 * @since 6.5
 */
public final class ServletPatternRequestMatcher implements RequestMatcher {

	private final String pattern;

	public ServletPatternRequestMatcher(String pattern) {
		this.pattern = pattern;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return this.pattern.equals(getServletMapping(request).getPattern());
	}

	@Nullable
	private static HttpServletMapping getServletMapping(HttpServletRequest request) {
		HttpServletMapping mapping = (HttpServletMapping) request.getAttribute(RequestDispatcher.INCLUDE_MAPPING);
		return (mapping != null) ? mapping : request.getHttpServletMapping();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof ServletPatternRequestMatcher that)) {
			return false;
		}
		return Objects.equals(this.pattern, that.pattern);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(this.pattern);
	}

	@Override
	public String toString() {
		return "ServletPatternRequestMatcher [pattern='" + this.pattern + "]";
	}

}
