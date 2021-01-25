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

import java.util.function.Consumer;

/**
 * Encodes and signs JWTs, implementations may also support encryption.
 */
public interface JwtEncoderAlternative {

	/**
	 * Return a partial application for specifying any claims or headers needed in the JWT
	 *
	 * @return a partial application
	 */
	JwtMutator<?> encoder();

	/**
	 * It's more natural to return a builder-like object since encoding a
	 * JWT is a sophisticated operation with a hard-to-reverse result
	 *
	 * @param <B>
	 */
	interface JwtMutator<B extends JwtMutator<B>> {
		/**
		 * By expressing this as optional method parameters, it allows the
		 * API to add more parameters in the future. For example, JWE support
		 * could be added by adding a {@code jweHeaders} method
		 *
		 * This kind of separation also allows for clarity when the caller
		 * wants to indicate the JWS algorithm and the JWE algorithm.
		 */
		B jwsHeaders(Consumer<JwsHeaderMutator<?>> headersConsumer);
		B claims(Consumer<JwtClaimMutator<?>> claimsConsumer);
		String encode();
	}
}
