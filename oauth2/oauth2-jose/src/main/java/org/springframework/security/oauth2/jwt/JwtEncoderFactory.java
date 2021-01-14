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

import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;

public interface JwtEncoderFactory {
	EncoderSpec<?> encoder(JoseHeader header);

	default EncoderSpec<?> encoder(JwsAlgorithm algorithm) {
		return encoder(JoseHeader.withAlgorithm(algorithm).build());
	}

	interface EncoderSpec<T extends EncoderSpec<T>> {
		EncoderSpec<?> claims(Consumer<Map<String, Object>> claimsConsumer);

		default EncoderSpec<?> claim(String name, Object value) {
			return claims((claims) -> claims.put(name, value));
		}

		default EncoderSpec<?> audience(Collection<String> audience) {
			return claim(JwtClaimNames.AUD, audience);
		}

		default EncoderSpec<?> expiresAt(Instant expiresAt) {
			return claim(JwtClaimNames.EXP, expiresAt);
		}

		default EncoderSpec<?> jti(String jti) {
			return claim(JwtClaimNames.JTI, jti);
		}

		default EncoderSpec<?> issuedAt(Instant issuedAt) {
			return claim(JwtClaimNames.IAT, issuedAt);
		}

		default EncoderSpec<?> issuer(String issuer) {
			return claim(JwtClaimNames.ISS, issuer);
		}

		default  EncoderSpec<?> notBefore(Instant notBefore) {
			return claim(JwtClaimNames.NBF, notBefore);
		}

		default EncoderSpec<?> subject(String subject) {
			return claim(JwtClaimNames.SUB, subject);
		}

		Jwt encode();
	}
}
