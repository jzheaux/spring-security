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

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.resourceserver.BearerTokenError;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * A class for formulating OAuth 2.0
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>
 * error responses
 *
 * @author Josh Cummings
 * @author Vedran Pavic
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate
 */
public final class BearerTokenErrorUtils {
	public static String computeWWWAuthenticateHeaderValue(String realmName) {
		return computeWWWAuthenticateHeaderValue(parameters(realmName));
	}

	public static String computeWWWAuthenticateHeaderValue(String realmName, OAuth2Error error) {
		if ( error instanceof BearerTokenError ) {
			return computeWWWAuthenticateHeaderValue(
					realmName,
					error.getErrorCode(),
					error.getDescription(),
					error.getUri(),
					((BearerTokenError) error).getScope());
		} else {
			return computeWWWAuthenticateHeaderValue(
					realmName,
					error.getErrorCode(),
					error.getDescription(),
					error.getUri(),
					null);
		}
	}

	private static String computeWWWAuthenticateHeaderValue(
			String realmName,
			String error,
			String description,
			String uri,
			String scope) {

		Map<String, String> parameters = parameters(realmName);

		parameters.put("error", error);

		if (description != null) {
			parameters.put("error_description", description);
		}

		if (uri != null) {
			parameters.put("error_uri", uri);
		}

		if (scope != null) {
			parameters.put("scope", scope);
		}

		return computeWWWAuthenticateHeaderValue(parameters);
	}

	private static Map<String, String> parameters(String realmName) {
		Map<String, String> parameters = new LinkedHashMap<>();

		if (realmName != null) {
			parameters.put("realm", realmName);
		}

		return parameters;
	}

	private static String computeWWWAuthenticateHeaderValue(Map<String, String> parameters) {
		String wwwAuthenticate = "Bearer";
		if (!parameters.isEmpty()) {
			wwwAuthenticate += parameters.entrySet().stream()
					.map(attribute -> attribute.getKey() + "=\"" + attribute.getValue() + "\"")
					.collect(Collectors.joining(", ", " ", ""));
		}

		return wwwAuthenticate;
	}
}
