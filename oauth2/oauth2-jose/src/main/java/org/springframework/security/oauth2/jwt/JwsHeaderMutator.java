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
	 * Set a header that is critical for decoders to understand
	 *
	 * @param name the header name
	 * @param value the header value
	 * @return the {@link JwsHeaderMutator} for more customizations
	 */
	default M criticalHeader(String name, Object value) {
		return criticalHeaders((crit) -> crit.put(name, value));
	}

	M criticalHeaders(Consumer<Map<String, Object>> criticalHeadersConsumer);

	/**
	 * Set a header
	 *
	 * Note that key-specific headers are typically best specified by the encoder
	 * itself.
	 *
	 * See {@link JwtEncoderAlternative}
	 */
	default M header(String name, Object value) {
		return headers((headers) -> headers.put(name, value));
	}

	M headers(Consumer<Map<String, Object>> headersConsumer);
}
