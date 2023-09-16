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

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import jakarta.servlet.MultipartConfigElement;
import jakarta.servlet.Servlet;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.ServletSecurityElement;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class RequestMatchersBuilderTests {

	@Test
	void matchersWhenDefaultDispatcherServletThenMvc() {
		MockServletContext servletContext = MockServletContext.mvc();
		RequestMatchersBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher[] matchers = builder.matchers("/mvc");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		MvcRequestMatcher matcher = (MvcRequestMatcher) matchers[0];
		assertThat(ReflectionTestUtils.getField(matcher, "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/mvc");
	}

	@Test
	void httpMethodMatchersWhenDefaultDispatcherServletThenMvc() {
		MockServletContext servletContext = MockServletContext.mvc();
		RequestMatchersBuilder builder = requestMatchersBuilder(servletContext);
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
		RequestMatchersBuilder builder = requestMatchersBuilder(servletContext);
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
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		RequestMatchersBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher[] matchers = builder.matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		MvcRequestMatcher matcher = (MvcRequestMatcher) matchers[0];
		assertThat(ReflectionTestUtils.getField(matcher, "servletPath")).isEqualTo("/mvc");
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenOnlyDefaultServletThenAnt() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		RequestMatchersBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher[] matchers = builder.matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		AntPathRequestMatcher matcher = (AntPathRequestMatcher) matchers[0];
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenNoHandlerMappingIntrospectorThenAnt() {
		MockServletContext servletContext = MockServletContext.mvc();
		RequestMatchersBuilder builder = requestMatchersBuilder(servletContext, (context) -> {
		});
		RequestMatcher[] matchers = builder.matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		AntPathRequestMatcher matcher = (AntPathRequestMatcher) matchers[0];
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenNoDispatchServletThenAnt() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		RequestMatchersBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher[] matchers = builder.matchers("/services/endpoint");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		AntPathRequestMatcher matcher = (AntPathRequestMatcher) matchers[0];
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/services/endpoint");
	}

	@Test
	void matchersWhenMixedServletsThenRequiresServletPath() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		RequestMatchersBuilder builder = requestMatchersBuilder(servletContext);
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> builder.matchers("/services/endpoint"));
		RequestMatcher[] matchers = builder.servletPath("/services").matchers("/endpoint");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/services/endpoint");
		matchers = builder.servletPath("/").matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isEqualTo("/");
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenDispatcherServletNotDefaultThenRequiresServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		RequestMatchersBuilder builder = requestMatchersBuilder(servletContext);
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> builder.matchers("/controller"));
		RequestMatcher[] matchers = builder.servletPath("/mvc").matchers("/controller");
		assertThat(matchers[0]).isInstanceOf(MvcRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "servletPath")).isEqualTo("/mvc");
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/controller");
		matchers = builder.servletPath("/").matchers("/endpoint");
		assertThat(matchers[0]).isInstanceOf(AntPathRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matchers[0], "pattern")).isEqualTo("/endpoint");
	}

	@Test
	void matcherWhenFacesServletThenAnt() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("facesServlet", Servlet.class).addMapping("/faces/", "*.jsf", "*.faces", "*.xhtml");
		RequestMatchersBuilder builder = requestMatchersBuilder(servletContext);
		RequestMatcher matcher = builder.servletPath("/faces/").matcher();
		assertThat(matcher).isInstanceOf(AntPathRequestMatcher.class);
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/faces/");
	}

	RequestMatchersBuilder requestMatchersBuilder(ServletContext servletContext) {
		return requestMatchersBuilder(servletContext,
				(context) -> context.registerBean("mvcHandlerMappingIntrospector", HandlerMappingIntrospector.class));
	}

	RequestMatchersBuilder requestMatchersBuilder(ServletContext servletContext,
			Consumer<GenericWebApplicationContext> consumer) {
		GenericWebApplicationContext context = new GenericWebApplicationContext(servletContext);
		consumer.accept(context);
		context.refresh();
		return new RequestMatchersBuilder(context);
	}

	static class MockServletContext extends org.springframework.mock.web.MockServletContext {

		private final Map<String, ServletRegistration> registrations = new LinkedHashMap<>();

		static MockServletContext mvc() {
			MockServletContext servletContext = new MockServletContext();
			servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/");
			return servletContext;
		}

		@NonNull
		@Override
		public ServletRegistration.Dynamic addServlet(@NonNull String servletName, Class<? extends Servlet> clazz) {
			ServletRegistration.Dynamic dynamic = new MockServletRegistration(servletName, clazz);
			this.registrations.put(servletName, dynamic);
			return dynamic;
		}

		@NonNull
		@Override
		public Map<String, ? extends ServletRegistration> getServletRegistrations() {
			return this.registrations;
		}

		private static class MockServletRegistration implements ServletRegistration.Dynamic {

			private final String name;

			private final Class<?> clazz;

			private final Set<String> mappings = new LinkedHashSet<>();

			MockServletRegistration(String name, Class<?> clazz) {
				this.name = name;
				this.clazz = clazz;
			}

			@Override
			public void setLoadOnStartup(int loadOnStartup) {

			}

			@Override
			public Set<String> setServletSecurity(ServletSecurityElement constraint) {
				return null;
			}

			@Override
			public void setMultipartConfig(MultipartConfigElement multipartConfig) {

			}

			@Override
			public void setRunAsRole(String roleName) {

			}

			@Override
			public void setAsyncSupported(boolean isAsyncSupported) {

			}

			@Override
			public Set<String> addMapping(String... urlPatterns) {
				this.mappings.addAll(Arrays.asList(urlPatterns));
				return this.mappings;
			}

			@Override
			public Collection<String> getMappings() {
				return this.mappings;
			}

			@Override
			public String getRunAsRole() {
				return null;
			}

			@Override
			public String getName() {
				return this.name;
			}

			@Override
			public String getClassName() {
				return this.clazz.getName();
			}

			@Override
			public boolean setInitParameter(String name, String value) {
				return false;
			}

			@Override
			public String getInitParameter(String name) {
				return null;
			}

			@Override
			public Set<String> setInitParameters(Map<String, String> initParameters) {
				return null;
			}

			@Override
			public Map<String, String> getInitParameters() {
				return null;
			}

		}

	}

}
