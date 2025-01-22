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

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherBuilder;

import static org.assertj.core.api.Assertions.assertThat;

class ServletRequestMatcherBuildersTests {

	@Test
	void patternWhenServletPathThenMatchesOnlyServletPath() {
		RequestMatcherBuilder builder = ServletRequestMatcherBuilders.servletPath("/servlet/path");
		RequestMatcher requestMatcher = builder.pattern(HttpMethod.GET, "/endpoint");
		assertThat(requestMatcher.matches(request("/servlet/path/endpoint", "/servlet/path"))).isTrue();
		assertThat(requestMatcher.matches(request("/endpoint", ""))).isFalse();
	}

	@Test
	void patternWhenDefaultServletThenMatchesOnlyDefaultServlet() {
		RequestMatcherBuilder builder = ServletRequestMatcherBuilders.defaultServlet();
		RequestMatcher requestMatcher = builder.pattern(HttpMethod.GET, "/endpoint");
		assertThat(requestMatcher.matches(request("/servlet/path/endpoint", "/servlet/path"))).isFalse();
		assertThat(requestMatcher.matches(request("/endpoint", ""))).isTrue();
	}

	HttpServletRequest request(String path, String servletPath) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
		request.setServletPath(servletPath);
		return request;
	}

}
