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
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.util.CollectionUtils;

public class NimbusJwsEncoderFactory implements JwtEncoderFactory {
	private final JWKSource<SecurityContext> jwks;

	public NimbusJwsEncoderFactory(JWKSource<SecurityContext> jwks) {
		this.jwks = jwks;
	}

	@Override
	public EncoderSpec<?> encoder(JoseHeader header) {
		// look up JWK
		JWK jwk = jwk(header);
		return new NimbusEncoderSpec(jwk)
				.header("kid", jwk.getKeyID())
				.header("typ", "JWT")
				.header("alg", header.getAlgorithm())
				.issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(3600));
	}

	private JWK jwk(JoseHeader header) {
		try {
			JWSHeader jwsHeader = JWSHeader.parse(header.getHeaders());
			JWKSelector selector = new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader));
			return CollectionUtils.firstElement(this.jwks.get(selector, null));
		} catch (Exception e) {
			throw new JwtException("Failed to lookup JWK", e);
		}
	}

	private final class NimbusEncoderSpec implements EncoderSpec<NimbusEncoderSpec> {
		private final JWSSigner signer;
		private final Map<String, Object> headers = new LinkedHashMap<>();
		private final Map<String, Object> claims = new LinkedHashMap<>();

		private NimbusEncoderSpec(JWK jwk) {
			try {
				this.signer = new DefaultJWSSignerFactory().createJWSSigner(jwk);
			} catch (Exception e) {
				throw new JwtException("Failed to sign JWT", e);
			}
		}

		NimbusEncoderSpec header(String name, Object value) {
			this.headers.put(name, value);
			return this;
		}

		@Override
		public EncoderSpec<?> claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		@Override
		public EncoderSpec<?> expiresAt(Instant expiresAt) {
			return claim(JwtClaimNames.EXP, expiresAt.getEpochSecond());
		}

		@Override
		public EncoderSpec<?> issuedAt(Instant issuedAt) {
			return claim(JwtClaimNames.IAT, issuedAt.getEpochSecond());
		}

		@Override
		public EncoderSpec<?> notBefore(Instant notBefore) {
			return claim(JwtClaimNames.NBF, notBefore.getEpochSecond());
		}

		@Override
		public Jwt encode() {
			JWSHeader header = jwsHeader(this.headers);
			JWTClaimsSet claims = jwtClaimSet(this.claims);
			SignedJWT jwt = new SignedJWT(header, claims);
			sign(jwt, this.signer);
			Instant iat = toInstant(this.claims.get(JwtClaimNames.IAT));
			Instant exp = toInstant(this.claims.get(JwtClaimNames.EXP));
			String tokenValue = jwt.serialize();
			return new Jwt(tokenValue, iat, exp, this.headers, this.claims);
		}

		private Instant toInstant(Object timestamp) {
			if (timestamp instanceof Date) {
				return ((Date) timestamp).toInstant();
			}
			if (timestamp instanceof Instant) {
				return (Instant) timestamp;
			}
			throw new IllegalArgumentException("timestamps must be of type Date");
		}
	}

	private JWSHeader jwsHeader(Map<String, Object> headers) {
		try {
			return JWSHeader.parse(headers);
		} catch (Exception e) {
			throw new JwtException("Failed to read JWS header", e);
		}
	}

	private JWTClaimsSet jwtClaimSet(Map<String, Object> claims) {
		try {
			return JWTClaimsSet.parse(claims);
		} catch (Exception e) {
			throw new JwtException("Failed to read claims", e);
		}
	}

	private void sign(SignedJWT jwt, JWSSigner signer) {
		try {
			jwt.sign(signer);
		} catch (Exception e) {
			throw new JwtException("Failed to sign JWT", e);
		}
	}
}
