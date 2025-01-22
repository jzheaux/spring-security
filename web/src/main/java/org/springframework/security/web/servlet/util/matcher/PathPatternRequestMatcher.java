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

import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.RequestPath;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherBuilder;
import org.springframework.util.Assert;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * A {@link RequestMatcher} that uses {@link PathPattern}s to match against each
 * {@link HttpServletRequest}. Specifically, this means that the class anticipates that
 * the provided pattern does not include the servlet path in order to align with Spring
 * MVC.
 *
 * <p>
 * Note that the {@link org.springframework.web.servlet.HandlerMapping} that contains the
 * related URI patterns must be using the same
 * {@link org.springframework.web.util.pattern.PathPatternParser} configured in this
 * class.
 * </p>
 *
 * <p>
 * The pattern must be specified separately from the servlet path. If no servlet path is
 * given, the pattern is still assumed to be relative to the servlet path.
 * </p>
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class PathPatternRequestMatcher implements RequestMatcher {

	private final PathPattern pattern;

	private String servletPath;

	private HttpMethod method;

	PathPatternRequestMatcher(PathPattern pattern) {
		this.pattern = pattern;
	}

	/**
	 * Create a {@link Builder} for creating {@link PathPattern}-based request matchers.
	 * That is, matchers that anticipate patterns do not specify the servlet path.
	 * @return the {@link Builder}
	 */
	public static Builder builder() {
		return new Builder(PathPatternParser.defaultInstance);
	}

	/**
	 * Create a {@link Builder} for creating {@link PathPattern}-based request matchers.
	 * That is, matchers that anticipate patterns do not specify the servlet path.
	 * @param parser the {@link PathPatternParser}; only needed when different from
	 * {@link PathPatternParser#defaultInstance}
	 * @return the {@link Builder}
	 */
	public static Builder withPathPatternParser(PathPatternParser parser) {
		return new Builder(parser);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean matches(HttpServletRequest request) {
		return matcher(request).isMatch();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public MatchResult matcher(HttpServletRequest request) {
		if (this.method != null && !this.method.name().equals(request.getMethod())) {
			return MatchResult.notMatch();
		}
		if (this.servletPath != null && !this.servletPath.equals(request.getServletPath())) {
			return MatchResult.notMatch();
		}
		PathContainer path = getRequestPath(request).pathWithinApplication();
		PathPattern.PathMatchInfo info = this.pattern.matchAndExtract(path);
		return (info != null) ? MatchResult.match(info.getUriVariables()) : MatchResult.notMatch();
	}

	void setServletPath(String servletPath) {
		this.servletPath = servletPath;
	}

	void setMethod(HttpMethod method) {
		this.method = method;
	}

	private RequestPath getRequestPath(HttpServletRequest request) {
		return ServletRequestPathUtils.hasParsedRequestPath(request)
				? ServletRequestPathUtils.getParsedRequestPath(request)
				: ServletRequestPathUtils.parseAndCache(request);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(Object o) {
		if (!(o instanceof PathPatternRequestMatcher that)) {
			return false;
		}
		return Objects.equals(this.pattern, that.pattern) && Objects.equals(this.servletPath, that.servletPath)
				&& Objects.equals(this.method, that.method);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {
		return Objects.hash(this.pattern, this.servletPath, this.method);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return "PathPatternRequestMatcher [pattern=" + this.pattern + ", servletPath=" + this.servletPath + ", method="
				+ this.method + ']';
	}

	/**
	 * A builder for {@link PathPatternRequestMatcher}
	 *
	 * @author Marcus Da Coregio
	 * @since 6.5
	 */
	public static final class Builder implements RequestMatcherBuilder {

		private final PathPatternParser parser;

		private String servletPath;

		/**
		 * Construct a new instance of this builder
		 */
		public Builder(PathPatternParser parser) {
			Assert.notNull(parser, "pathPatternParser cannot be null");
			this.parser = parser;
		}

		/**
		 * Match requests that have this {@code servletPath}
		 * @param servletPath the servlet path to use
		 * @return the {@link PathPatternRequestMatcher.Builder} for further configuration
		 */
		public Builder servletPath(String servletPath) {
			this.servletPath = servletPath;
			return this;
		}

		/**
		 * Creates an {@link PathPatternRequestMatcher} that uses the provided
		 * {@code pattern} and HTTP {@code method} to match.
		 * <p>
		 * If the {@code pattern} is a path, it must be specified relative to the servlet
		 * path, even if no {@link #servletPath} is specified.
		 * </p>
		 * @param method the {@link HttpMethod}, can be null
		 * @param pattern the pattern used to match; if a path, must be relative to the
		 * servlet path, even if no {@link #servletPath} is specified
		 * @return the generated {@link PathPatternRequestMatcher}
		 */
		public PathPatternRequestMatcher pattern(HttpMethod method, String pattern) {
			String parsed = this.parser.initFullPathPattern(pattern);
			PathPattern pathPattern = this.parser.parse(parsed);
			PathPatternRequestMatcher requestMatcher = new PathPatternRequestMatcher(pathPattern);
			requestMatcher.setServletPath(this.servletPath);
			requestMatcher.setMethod(method);
			return requestMatcher;
		}

	}

}
