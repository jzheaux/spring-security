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

import jakarta.servlet.Servlet;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.servlet.MockServletContext;
import org.springframework.security.web.servlet.util.matcher.ServletRequestMatcherBuilders.PathDeducingRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherBuilder;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.util.ServletRequestPathUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ServletRequestMatcherBuildersTests {

	@Test
	void patternWhenServletPathThenUsesPathPattern() {
		RequestMatcherBuilder builder = ServletRequestMatcherBuilders.servletPath("/servlet/path");
		RequestMatcher requestMatcher = builder.pattern(HttpMethod.GET, "/endpoint");
		assertThat(requestMatcher.toString()).contains(PathPatternRequestMatcher.class.getSimpleName());
	}

	@Test
	void patternWhenDefaultServletThenUsesPathPattern() {
		RequestMatcherBuilder builder = ServletRequestMatcherBuilders.defaultServlet();
		RequestMatcher requestMatcher = builder.pattern(HttpMethod.GET, "/endpoint");
		assertThat(requestMatcher.toString()).contains(PathPatternRequestMatcher.class.getSimpleName());
	}

	@Test
	void patternWhenServletPathDeducingThenUsesComposite() {
		RequestMatcherBuilder builder = ServletRequestMatcherBuilders.servletPathDeducing();
		RequestMatcher requestMatcher = builder.pattern(HttpMethod.GET, "/endpoint");
		assertThat(requestMatcher).isInstanceOf(PathDeducingRequestMatcher.class);
	}

	@Test
	void requestMatchersWhenAmbiguousServletsThenException() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/");
		servletContext.addServlet("servletTwo", DispatcherServlet.class).addMapping("/servlet/*");
		RequestMatcher requestMatcher = ServletRequestMatcherBuilders.servletPathDeducing().pattern("/**");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> requestMatcher.matches(new MockHttpServletRequest(servletContext)));
	}

	@Test
	void requestMatchersWhenMultipleDispatcherServletMappingsThenException() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/", "/mvc/*");
		RequestMatcher requestMatcher = ServletRequestMatcherBuilders.servletPathDeducing().pattern("/**");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> requestMatcher.matcher(new MockHttpServletRequest(servletContext)));
	}

	@Test
	void requestMatchersWhenPathDispatcherServletAndOtherServletsThenException() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		RequestMatcher requestMatcher = ServletRequestMatcherBuilders.servletPathDeducing().pattern("/**");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> requestMatcher.matcher(new MockHttpServletRequest(servletContext)));
	}

	@Test
	void requestMatchersWhenUnmappableServletsThenSkips() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/");
		servletContext.addServlet("servletTwo", Servlet.class);
		PathDeducingRequestMatcher requestMatcher = (PathDeducingRequestMatcher) ServletRequestMatcherBuilders
			.servletPathDeducing()
			.pattern("/**");
		RequestMatcher deduced = requestMatcher.requestMatcher(new MockHttpServletRequest(servletContext));
		assertThat(deduced.toString()).contains(PathPatternRequestMatcher.class.getSimpleName());
	}

	@Test
	void requestMatchersWhenOnlyDispatcherServletThenAllows() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		PathDeducingRequestMatcher requestMatcher = (PathDeducingRequestMatcher) ServletRequestMatcherBuilders
			.servletPathDeducing()
			.pattern("/**");
		RequestMatcher deduced = requestMatcher.requestMatcher(new MockHttpServletRequest(servletContext));
		assertThat(deduced.toString()).contains(PathPatternRequestMatcher.class.getSimpleName());
	}

	@Test
	void requestMatchersWhenImplicitServletsThenAllows() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("defaultServlet", Servlet.class);
		servletContext.addServlet("jspServlet", Servlet.class).addMapping("*.jsp", "*.jspx");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/");
		PathDeducingRequestMatcher requestMatcher = (PathDeducingRequestMatcher) ServletRequestMatcherBuilders
			.servletPathDeducing()
			.pattern("/**");
		RequestMatcher deduced = requestMatcher.requestMatcher(new MockHttpServletRequest(servletContext));
		assertThat(deduced.toString()).contains(PathPatternRequestMatcher.class.getSimpleName());
	}

	@Test
	void requestMatchersWhenPathBasedServletRequiresServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("path", Servlet.class).addMapping("/services/*");
		servletContext.addServlet("default", DispatcherServlet.class).addMapping("/");
		PathDeducingRequestMatcher requestMatcher = (PathDeducingRequestMatcher) ServletRequestMatcherBuilders
			.servletPathDeducing()
			.pattern("/services/**");
		RequestMatcher deduced = requestMatcher.requestMatcher(new MockHttpServletRequest(servletContext));
		assertThat(deduced.toString()).contains(PathPatternRequestMatcher.class.getSimpleName());
		MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET", "/services/endpoint");
		request.setServletPath("");
		assertThat(deduced.matcher(request).isMatch()).isTrue();
		ServletRequestPathUtils.clearParsedRequestPath(request);
		request.setServletPath("/services");
		request.setPathInfo("/endpoint");
		assertThat(deduced.matcher(request).isMatch()).isFalse();
	}

}
