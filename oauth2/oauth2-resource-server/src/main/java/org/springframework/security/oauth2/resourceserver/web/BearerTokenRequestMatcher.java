/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.resourceserver.web;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

/**
 * A request matcher for detecting when the request may contain a
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>
 *
 * @since 5.1
 * @author Josh Cummings
 */
public class BearerTokenRequestMatcher implements RequestMatcher {

	BearerTokenResolver resolver = new DefaultBearerTokenResolver();

	@Override
	public boolean matches(HttpServletRequest request) {
		return resolver.resolve(request) != null;
	}

	public void setBearerTokenResolver(BearerTokenResolver resolver) {
		Assert.notNull(resolver, "bearerTokenResolver cannot be null");
		this.resolver = resolver;
	}
}
