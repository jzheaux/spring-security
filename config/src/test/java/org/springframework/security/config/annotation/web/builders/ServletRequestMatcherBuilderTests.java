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

import java.util.function.Consumer;

import jakarta.servlet.Servlet;
import jakarta.servlet.ServletContext;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.MockServletContext;
import org.springframework.security.config.annotation.web.builders.ServletRequestMatcherBuilder.ServletPathAwareRequestMatcher;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ServletRequestMatcherBuilderTests {

	@Test
	void matchersWhenDefaultDispatcherServletThenMvc() {
		MockServletContext servletContext = MockServletContext.mvc();
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher[] matchers = builder.matchers("/mvc");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		MvcRequestMatcher matcher = (MvcRequestMatcher) matchers[0];
		assertThat(ReflectionTestUtils.getField(matcher, "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/mvc");
	}

	@Test
	void httpMethodMatchersWhenDefaultDispatcherServletThenMvc() {
		MockServletContext servletContext = MockServletContext.mvc();
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher[] matchers = builder.matchers(HttpMethod.GET, "/mvc");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		MvcRequestMatcher matcher = (MvcRequestMatcher) matchers[0];
		assertThat(ReflectionTestUtils.getField(matcher, "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/mvc");
		assertThat(ReflectionTestUtils.getField(matcher, "method")).isEqualTo(HttpMethod.GET);
	}

	@Test
	void matchersWhenPathDispatcherServletThenMvc() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher[] matchers = builder.matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		MvcRequestMatcher matcher = (MvcRequestMatcher) matchers[0];
		assertThat(ReflectionTestUtils.getField(matcher, "servletPath")).isEqualTo("/mvc");
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenAlsoExtraServletContainerMappingsThenMvc() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class);
		servletContext.addServlet("jspServlet", Servlet.class).addMapping("*.jsp", "*.jspx");
		servletContext.addServlet("facesServlet", Servlet.class).addMapping("/faces/", "*.jsf", "*.faces", "*.xhtml");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher[] matchers = builder.matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(ServletPathAwareRequestMatcher.class);
		MvcRequestMatcher matcher = ((ServletPathAwareRequestMatcher) matchers[0]).mvc;
		assertThat(ReflectionTestUtils.getField(matcher, "servletPath")).isEqualTo("/mvc");
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenOnlyDefaultServletThenAnt() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher[] matchers = builder.matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		AntPathRequestMatcher matcher = (AntPathRequestMatcher) matchers[0];
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenNoHandlerMappingIntrospectorThenException() {
		MockServletContext servletContext = MockServletContext.mvc();
		assertThatExceptionOfType(NoSuchBeanDefinitionException.class)
				.isThrownBy(() -> requestMatchersBuilder(servletContext, (context) -> {
				}));
	}

	@Test
	void matchersWhenNoDispatchServletThenAnt() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher[] matchers = builder.matchers("/services/endpoint");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		AntPathRequestMatcher matcher = (AntPathRequestMatcher) matchers[0];
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/services/endpoint");
	}

	@Test
	void matchersWhenMixedServletsThenRequiresServletPath() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThat(builder.matchers("/services/endpoint")[0]).isInstanceOf(ServletPathAwareRequestMatcher.class);
		RequestMatcher[] matchers = builder.servletPath("/services").matchers("/endpoint");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/services/endpoint");
		matchers = builder.servletPath("/").matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenDispatcherServletNotDefaultThenServletAware() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThat(builder.matchers("/controller")[0]).isInstanceOf(ServletPathAwareRequestMatcher.class);
		RequestMatcher[] matchers = builder.servletPath("/mvc").matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isEqualTo("/mvc");
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
		matchers = builder.servletPath("/").matchers("/endpoint");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/endpoint");
	}

	@Test
	void httpMatchersWhenDispatcherServletNotDefaultThenServletAware() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThat(builder.matchers(HttpMethod.GET, "/controller")[0])
				.isInstanceOf(ServletPathAwareRequestMatcher.class);
		RequestMatcher[] matchers = builder.servletPath("/mvc").matchers(HttpMethod.GET, "/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "method")).isEqualTo(HttpMethod.GET);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isEqualTo("/mvc");
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
		matchers = builder.servletPath("/").matchers(HttpMethod.GET, "/endpoint");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "httpMethod")).isEqualTo(HttpMethod.GET);
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/endpoint");
	}

	@Test
	void matchersWhenTwoDispatcherServletsThenRequiresServletPath() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("two", DispatcherServlet.class).addMapping("/other/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> builder.matchers("/controller"));
		RequestMatcher[] matchers = builder.servletPath("/").matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
		matchers = builder.servletPath("/other").matchers("/endpoint");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isEqualTo("/other");
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/endpoint");
	}

	@Test
	void matchersWhenMoreThanOneMappingThenRequiresServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/", "/two/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> builder.matchers("/controller"));
		RequestMatcher[] matchers = builder.servletPath("/").matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
		matchers = builder.servletPath("/two").matchers("/endpoint");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isEqualTo("/two");
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/endpoint");
	}

	@Test
	void matchersWhenMoreThanOneMappingAndDefaultServletsThenRequiresServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/", "/two/*");
		servletContext.addServlet("jspServlet", Servlet.class).addMapping("*.jsp", "*.jspx");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> builder.matchers("/controller"));
		RequestMatcher[] matchers = builder.servletPath("/").matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
		matchers = builder.servletPath("/two").matchers("/endpoint");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isEqualTo("/two");
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/endpoint");
	}

	@Test
	void mvcMatchersWhenDispatcherServletThenMvc() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThat(builder.matchers("/controller")[0]).isInstanceOf(ServletPathAwareRequestMatcher.class);
		RequestMatcher[] matchers = builder.mvc().matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
		matchers = builder.servletPath("/services").matchers("/endpoint");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/services/endpoint");
	}

	@Test
	void mvcMatchersWhenNoDispatcherServletThenException() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> builder.mvc().matchers("/controller"));
	}

	@Test
	void mvcMatchersWhenTwoDispatcherServletsThenRequiresServletPath() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("two", DispatcherServlet.class).addMapping("/other/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> builder.mvc().matchers("/controller"));
		RequestMatcher[] matchers = builder.servletPath("/").matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
		matchers = builder.servletPath("/other").matchers("/endpoint");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isEqualTo("/other");
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/endpoint");
	}

	@Test
	void mvcMatchersWhenMoreThanOneMappingThenRequiresServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/", "/two/*");
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> builder.mvc().matchers("/controller"));
		RequestMatcher[] matchers = builder.servletPath("/").matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
		matchers = builder.servletPath("/two").matchers("/endpoint");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isEqualTo("/two");
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/endpoint");
	}

	@Test
	void servletPathWhenNoMatchingServletThenException() {
		MockServletContext servletContext = MockServletContext.mvc();
		ServletRequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> builder.servletPath("/wrong"));
	}

	ServletRequestMatcherBuilder requestMatchersBuilder(ServletContext servletContext) {
		return requestMatchersBuilder(servletContext,
				(context) -> context.registerBean("mvcHandlerMappingIntrospector", HandlerMappingIntrospector.class));
	}

	ServletRequestMatcherBuilder requestMatchersBuilder(ServletContext servletContext,
			Consumer<GenericWebApplicationContext> consumer) {
		GenericWebApplicationContext context = new GenericWebApplicationContext(servletContext);
		consumer.accept(context);
		context.refresh();
		return new ServletRequestMatcherBuilder(context);
	}

}
