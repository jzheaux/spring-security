/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.http;

import jakarta.servlet.http.HttpServletRequest;
import org.w3c.dom.Element;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.servlet.util.matcher.ServletRequestMatcherBuilders;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherBuilder;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * Defines the {@link RequestMatcher} types supported by the namespace.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public enum MatcherType {

	ant(AntPathRequestMatcher.class), regex(RegexRequestMatcher.class), ciRegex(RegexRequestMatcher.class),
	mvc(MvcRequestMatcherFactoryBean.class);

	private static final String HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector";

	private static final boolean mvcPresent;

	private static final String ATT_MATCHER_TYPE = "request-matcher";

	final Class<? extends RequestMatcher> type;

	static {
		mvcPresent = ClassUtils.isPresent(HANDLER_MAPPING_INTROSPECTOR, MatcherType.class.getClassLoader());
	}

	MatcherType(Class<? extends RequestMatcher> type) {
		this.type = type;
	}

	public BeanDefinition createMatcher(ParserContext pc, String path, String method) {
		return createMatcher(pc, path, method, null);
	}

	public BeanDefinition createMatcher(ParserContext pc, String path, String method, String servletPath) {
		if (("/**".equals(path) || "**".equals(path)) && method == null) {
			return new RootBeanDefinition(AnyRequestMatcher.class);
		}
		BeanDefinitionBuilder matcherBldr = BeanDefinitionBuilder.rootBeanDefinition(this.type);
		if (this == mvc) {
			matcherBldr.addConstructorArgValue(new RootBeanDefinition(HandlerMappingIntrospectorFactoryBean.class));
		}
		matcherBldr.addConstructorArgValue(path);
		if (this == mvc) {
			matcherBldr.addPropertyValue("method", (StringUtils.hasText(method) ? HttpMethod.valueOf(method) : null));
			matcherBldr.addPropertyValue("servletPath", servletPath);
		}
		else {
			matcherBldr.addConstructorArgValue(method);
		}
		if (this == ciRegex) {
			matcherBldr.addConstructorArgValue(true);
		}
		return matcherBldr.getBeanDefinition();
	}

	static MatcherType fromElement(Element elt) {
		if (StringUtils.hasText(elt.getAttribute(ATT_MATCHER_TYPE))) {
			return valueOf(elt.getAttribute(ATT_MATCHER_TYPE));
		}

		return ant;
	}

	static MatcherType fromElementOrMvc(Element elt) {
		String matcherTypeName = elt.getAttribute(ATT_MATCHER_TYPE);
		if (!StringUtils.hasText(matcherTypeName) && mvcPresent) {
			return MatcherType.mvc;
		}
		return MatcherType.fromElement(elt);
	}

	private static class MvcRequestMatcherFactoryBean implements FactoryBean<RequestMatcher>, RequestMatcher {

		private final HandlerMappingIntrospector introspector;

		private final String pattern;

		private PathPatternParser pathPatternParser = PathPatternParser.defaultInstance;

		private String servletPath;

		private HttpMethod method;

		public MvcRequestMatcherFactoryBean(HandlerMappingIntrospector introspector, String pattern) {
			this.introspector = introspector;
			this.pattern = pattern;
		}

		@Override
		public RequestMatcher getObject() {
			if (this.introspector.allHandlerMappingsUsePathPatternParser()) {
				RequestMatcherBuilder requestMatcherBuilder = (this.servletPath != null)
						? ServletRequestMatcherBuilders.servletPath(this.servletPath)
						: PathPatternRequestMatcher.withPathPatternParser(this.pathPatternParser);
				return requestMatcherBuilder.pattern(this.method, this.pattern);
			}
			return new MvcRequestMatcher.Builder(this.introspector).servletPath(this.servletPath)
				.pattern(this.method, this.pattern);
		}

		@Override
		public Class<?> getObjectType() {
			return RequestMatcher.class;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return getObject().matches(request);
		}

		public void setPathPatternParser(PathPatternParser pathPatternParser) {
			this.pathPatternParser = pathPatternParser;
		}

		public void setServletPath(String servletPath) {
			this.servletPath = servletPath;
		}

		public void setMethod(HttpMethod method) {
			this.method = method;
		}

	}

}
