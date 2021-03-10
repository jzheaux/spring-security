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
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * A claims mutator for the &quot;claims&quot; that may be contained in the JSON
 * object JWT Claims Set of a JSON Web Token (JWT).
 *
 * @author Josh Cummings
 * @since 5.5
 * @see JwtClaimNames
 * @see Jwt
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc7519#section-4.1">Registered Claim Names</a>
 */
public interface JwtClaimMutator<M extends JwtClaimMutator<M>> {

	/**
	 * Returns the Issuer {@code (iss)} claim which identifies the principal that issued
	 * the JWT.
	 * @return the Issuer identifier
	 */
	default M issuer(String uri) {
		return claim(JwtClaimNames.ISS, uri);
	}

	/**
	 * Returns the Subject {@code (sub)} claim which identifies the principal that is the
	 * subject of the JWT.
	 * @return the Subject identifier
	 */
	default M subject(String sub) {
		return claim(JwtClaimNames.SUB, sub);
	}

	/**
	 * Returns the Audience {@code (aud)} claim which identifies the recipient(s) that the
	 * JWT is intended for.
	 * @return the Audience(s) that this JWT intended for
	 */
	default M audience(List<String> audience) {
		return claim(JwtClaimNames.AUD, audience);
	}

	/**
	 * Returns the Expiration time {@code (exp)} claim which identifies the expiration
	 * time on or after which the JWT MUST NOT be accepted for processing.
	 * @return the Expiration time on or after which the JWT MUST NOT be accepted for
	 * processing
	 */
	default M expiresAt(Instant expiresAt) {
		return claim(JwtClaimNames.EXP, expiresAt);
	}

	/**
	 * Returns the Not Before {@code (nbf)} claim which identifies the time before which
	 * the JWT MUST NOT be accepted for processing.
	 * @return the Not Before time before which the JWT MUST NOT be accepted for
	 * processing
	 */
	default M notBefore(Instant notBefore) {
		return claim(JwtClaimNames.NBF, notBefore);
	}

	/**
	 * Returns the Issued at {@code (iat)} claim which identifies the time at which the
	 * JWT was issued.
	 * @return the Issued at claim which identifies the time at which the JWT was issued
	 */
	default M issuedAt(Instant issuedAt) {
		return claim(JwtClaimNames.IAT, issuedAt);
	}

	/**
	 * Sets the JWT ID {@code (jti)} claim which provides a unique identifier for the
	 * JWT.
	 * @return the {@link JwtClaimMutator} for more customizations
	 */
	default M id(String id) {
		return claim(JwtClaimNames.JTI, id);
	}

	default M claim(String name, Object value) {
		claims((claims) -> claims.put(name, value));
		return (M) this;
	}

	M claims(Consumer<Map<String, Object>> claimsConsumer);
}
