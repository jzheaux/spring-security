/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;

/**
 * This interface represents the minimal set of headers necessary to
 * specify a JWT.
 *
 * I like this interface due to the symmetry with Spring Security's claim accessors
 *
 */
public interface JwsHeaderMutator<M extends JwsHeaderMutator<M>> {
	/**
	 * Set the algorithm {@code (alg)} header which identifies the algorithm
	 * used when signing the JWS
	 *
	 * @return the {@link JwsHeaderMutator} for more customizations
	 */
	default M algorithm(JwsAlgorithm jws) {
		return header(JoseHeaderNames.ALG, jws);
	}

	/**
	 * The spec indicates that when a critical header is specified, it generates
	 * two actual headers. The first is the {@code crit}, which contains a
	 * list of the header names and the second is the header itself.
	 *
	 * Because of how easy it would be for an application to indicate the {@code crit}
	 * header, but not the actual value of that header, it's important this be
	 * a dedicated method.
	 *
	 * @param name
	 * @param value
	 * @return
	 */
	default M criticalHeader(String name, Object value) {
		return criticalHeaders((crit) -> crit.put(name, value));
	}

	M criticalHeaders(Consumer<Map<String, Object>> criticalHeadersConsumer);

	/**
	 * Since no other headers are required, and since those headers are quite easy to
	 * get wrong in the general case, I think it's best to leave other headers
	 * out for now.
	 *
	 * Generally speaking, those headers are for looking up keys anyway, which is something
	 * likely better decided centrally in an encoder instead of by the caller. And even if
	 * that's not the case, this method still exists so that an application can specify them if needed.
	 *
	 * @param name
	 * @param value
	 * @return
	 */
	default M header(String name, Object value) {
		return headers((headers) -> headers.put(name, value));
	}

	M headers(Consumer<Map<String, Object>> headersConsumer);
}
