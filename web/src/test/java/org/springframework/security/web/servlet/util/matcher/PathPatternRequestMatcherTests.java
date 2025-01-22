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

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.ServletRequestPathUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link PathPatternRequestMatcher}
 */
public class PathPatternRequestMatcherTests {

	@Test
	void matcherWhenPatternMatchesRequestThenMatchResult() {
		RequestMatcher matcher = PathPatternRequestMatcher.builder().pattern("/uri");
		assertThat(matcher.matches(request("/uri"))).isTrue();
	}

	@Test
	void matcherWhenPatternContainsPlaceholdersThenMatchResult() {
		RequestMatcher matcher = PathPatternRequestMatcher.builder().pattern("/uri/{username}");
		assertThat(matcher.matcher(request("/uri/bob")).getVariables()).containsEntry("username", "bob");
	}

	@Test
	void matcherWhenSameServletPathThenMatchResult() {
		RequestMatcher matcher = PathPatternRequestMatcher.builder().servletPath("/mvc").pattern("/uri");
		assertThat(matcher.matches(request("GET", "/mvc/uri", "/mvc"))).isTrue();
	}

	@Test
	void matcherWhenSameMethodThenMatchResult() {
		RequestMatcher matcher = PathPatternRequestMatcher.builder().pattern(HttpMethod.GET, "/uri");
		assertThat(matcher.matches(request("/uri"))).isTrue();
	}

	@Test
	void matcherWhenDifferentPathThenNotMatchResult() {
		RequestMatcher matcher = PathPatternRequestMatcher.builder()
			.servletPath("/mvc")
			.pattern(HttpMethod.GET, "/uri");
		assertThat(matcher.matches(request("GET", "/uri", ""))).isFalse();
	}

	@Test
	void matcherWhenDifferentMethodThenNotMatchResult() {
		RequestMatcher matcher = PathPatternRequestMatcher.builder()
			.servletPath("/mvc")
			.pattern(HttpMethod.GET, "/uri");
		assertThat(matcher.matches(request("POST", "/mvc/uri", "/mvc"))).isFalse();
	}

	@Test
	void matcherWhenNoServletPathThenMatches() {
		RequestMatcher matcher = PathPatternRequestMatcher.builder().pattern(HttpMethod.GET, "/uri");
		assertThat(matcher.matches(request("GET", "/mvc/uri", "/mvc"))).isTrue();
		assertThat(matcher.matches(request("GET", "/uri", ""))).isTrue();
	}

	@Test
	void matcherWhenNoMethodThenMatches() {
		RequestMatcher matcher = PathPatternRequestMatcher.builder().pattern("/uri");
		assertThat(matcher.matches(request("POST", "/uri", ""))).isTrue();
		assertThat(matcher.matches(request("GET", "/uri", ""))).isTrue();
	}

	MockHttpServletRequest request(String uri) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
		ServletRequestPathUtils.parseAndCache(request);
		return request;
	}

	MockHttpServletRequest request(String method, String uri, String servletPath) {
		MockHttpServletRequest request = new MockHttpServletRequest(method, uri);
		request.setServletPath(servletPath);
		ServletRequestPathUtils.parseAndCache(request);
		return request;
	}

}
