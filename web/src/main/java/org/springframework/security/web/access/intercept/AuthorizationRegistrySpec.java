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

package org.springframework.security.web.access.intercept;

import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * A specification for registering
 * {@link org.springframework.security.web.util.matcher.RequestMatcherEntry} instances
 *
 * <p>
 * Note that the leaf methods return {@code void} because
 * {@link org.springframework.security.web.util.matcher.RequestMatcherEntry} instances
 * should be registered by the implementation.
 *
 * @author Josh Cummings
 * @since 6.5
 */
public interface AuthorizationRegistrySpec {

	/**
	 * Match any of these URIs. May be ant patterns that end in {@code **}
	 *
	 * <p>
	 * The URI must start with a {@code /} and be relative to any context path
	 * </p>
	 * @param uris URIs to match on
	 * @return the {@link AuthorizationRegistrySpec} for more configuration
	 */
	AuthorizationRegistrySpec uris(String... uris);

	/**
	 * Match any of these {@code HttpMethod}s.
	 * @param methods the HTTP methods to match on
	 * @return the {@link AuthorizationRegistrySpec} for more configuration
	 */
	AuthorizationRegistrySpec methods(HttpMethod... methods);

	/**
	 * Match any of these {@link RequestMatcher}s.
	 * @param matchers the {@link RequestMatcher}s to match on
	 * @return the {@link AuthorizationRegistrySpec} for more configuration
	 */
	AuthorizationRegistrySpec matching(RequestMatcher... matchers);

	/**
	 * Complete the request matcher and move on to the authorization condition
	 *
	 * <p>
	 * If no request matchers have been specified when this method is called, an
	 * {@link org.springframework.security.web.util.matcher.AnyRequestMatcher} is used.
	 * @return the {@link AuthorizationSpec} for specifying the authorization condition
	 */
	AuthorizationSpec authorize();

	/**
	 * Register the entry, using {@code manager} as the authorization condition
	 *
	 * <p>
	 * If no request matchers have been specified when this method is called, an
	 * {@link org.springframework.security.web.util.matcher.AnyRequestMatcher} is used.
	 */
	void authorize(AuthorizationManager<RequestAuthorizationContext> manager);

	/**
	 * A builder specification for the authorization half of the
	 * {@link org.springframework.security.web.util.matcher.RequestMatcherEntry}
	 */
	interface AuthorizationSpec {

		/**
		 * Authorize everyone (permitAll)
		 */
		void everyone();

		/**
		 * Authorize no one (denyAll)
		 */
		void none();

		/**
		 * Authorize those who are authenticated
		 */
		void authenticated();

		/**
		 * Authorize those who have at least one of the given {@code roles}
		 */
		void roles(String... roles);

		/**
		 * Authorize those who have at least one of the given {@code authorities}
		 */
		void authorities(String... authorities);

		/**
		 * Authorize those who are anonymous
		 */
		void anonymous();

		/**
		 * Authorize those who are authenticated via remember me
		 */
		void rememberMe();

		/**
		 * Authorize those who are authenticated and not via remember me
		 */
		void fullyAuthenticated();

	}

}
