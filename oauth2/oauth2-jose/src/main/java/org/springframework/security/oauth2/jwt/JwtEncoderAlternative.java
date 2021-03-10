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

	enum EncodingMode { SIGN, ENCRYPT, SIGN_THEN_ENCRYPT }

	/**
	 * Return a {@link JwtMutator} for specifying any claims or headers needed in the JWT
	 *
	 * @return a parameter mutator
	 */
	JwtMutator<?> encoder();

	/**
	 * A parameter mutator for specifying headers and claims to encode
	 */
	interface JwtMutator<B extends JwtMutator<B>> {
		/**
		 * Mutate the JWS headers
		 *
		 * @param headersConsumer the {@link Consumer} that mutates the JWS headers
		 * @return the {@link JwtMutator} for further customizations
		 */
		B jwsHeaders(Consumer<JwsHeaderMutator<?>> headersConsumer);

		/**
		 * Mutate the JWE headers
		 *
		 * @param headersConsumer the {@link Consumer} that mutates the JWS headers
		 * @return the {@link JwtMutator} for further customizations
		 */
		B jweHeaders(Consumer<JweHeaderMutator<?>> headersConsumer);

		/**
		 * Mutate the JWT Claims Set
		 *
		 * @param claimsConsumer the {@link Consumer} that mutates the JWT Claims Set
		 * @return the {@link JwtMutator} for further customizations
		 */
		B claims(Consumer<JwtClaimMutator<?>> claimsConsumer);

		/**
		 * Sign and serialize the JWT
		 *
		 * @return the signed and serialized JWT
		 */
		String encode();

		/**
		 * Encode the JWT according to the specified {@link EncodingMode}
		 *
		 * @return the signed and serialized JWT
		 */
		String encode(EncodingMode mode);
	}
}
