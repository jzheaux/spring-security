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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;

/**
 * Signs and serialized a JWT using the Nimbus library
 */
public class NimbusJwtEncoder implements JwtEncoderAlternative {
	private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

	private JwsAlgorithm defaultAlgorithm = SignatureAlgorithm.RS256;
	private JWKSource<SecurityContext> jwksSource;

	public void setJwkSource(JWKSource<SecurityContext> jwksSource) {
		Assert.notNull(jwksSource, "jwkSelector cannot be null");
		this.jwksSource = jwksSource;
	}

	@Override
	public NimbusJwtMutator encoder() {
		Instant now = Instant.now();
		return new NimbusJwtMutator(this.jwksSource)
				.jwsHeaders((jws) -> jws
						.algorithm(this.defaultAlgorithm)
						.header(JoseHeaderNames.TYP, "JWT")
				)
				.claims((claims) -> claims
						.issuedAt(now)
						.expiresAt(now.plusSeconds(3600))
						.notBefore(now)
				);
	}

	public static final class NimbusJwtMutator implements JwtMutator<NimbusJwtMutator> {
		private final JWSSignerFactory jwsSignerFactory = new DefaultJWSSignerFactory();
		private final JWKSource<SecurityContext> jwkSource;
		private final NimbusJwtClaimMutator claims = new NimbusJwtClaimMutator();
		private final NimbusJwsHeaderMutator jwsHeaders = new NimbusJwsHeaderMutator();

		private JWK jwk;
		private SecurityContext context;

		private NimbusJwtMutator(JWKSource<SecurityContext> jwkSource) {
			this.jwkSource = jwkSource;
		}

		@Override
		public NimbusJwtMutator jwsHeaders(Consumer<JwsHeaderMutator<?>> headersConsumer) {
			headersConsumer.accept(this.jwsHeaders);
			return this;
		}

		/**
		 * Use this {@link JWK} to sign the JWT
		 */
		public NimbusJwtMutator jwsKey(JWK jwk) {
			this.jwk = jwk;
			if (this.jwk.getKeyID() != null) {
				this.jwsHeaders.headers.put(JoseHeaderNames.KID, this.jwk.getKeyID());
			}
			if (this.jwk.getX509CertSHA256Thumbprint() != null) {
				this.jwsHeaders.headers.put(JoseHeaderNames.X5T, this.jwk.getX509CertSHA256Thumbprint().toString());
			}
			return this;
		}

		/**
		 * Send this {@link SecurityContext} to Nimbus's signing infrastructure
		 */
		public NimbusJwtMutator jwsSecurityContext(SecurityContext context) {
			this.context = context;
			return this;
		}

		@Override
		public NimbusJwtMutator claims(Consumer<JwtClaimMutator<?>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		@Override
		public String encode() {
			if (this.jwk == null) {
				if (this.context instanceof JWKSecurityContext) {
					this.jwk = ((JWKSecurityContext) this.context).getKeys().iterator().next();
				} else if (this.jwkSource != null) {
					jwsKey(selectJwk());
				} else {
					throw new IllegalStateException("Could not derive any key");
				}
			}
			return sign().serialize();
		}

		private JWK selectJwk() {
			List<JWK> jwks;
			try {
				JWSHeader jwsHeader = this.jwsHeaders.jwsHeader();
				JWKSelector jwkSelector = new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader));
				jwks = this.jwkSource.get(jwkSelector, this.context);
			}
			catch (Exception ex) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
						"Failed to select a JWK signing key -> " + ex.getMessage()), ex);
			}

			if (jwks.isEmpty()) {
				throw new JwtEncodingException(
						String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to select a JWK signing key"));
			}

			return jwks.get(0);
		}

		private SignedJWT sign() {
			JWSHeader jwsHeader = this.jwsHeaders.jwsHeader();
			JWTClaimsSet jwtClaimsSet = this.claims.jwtClaimsSet();

			SignedJWT signedJwt = new SignedJWT(jwsHeader, jwtClaimsSet);
			try {
				JWSSigner signer = this.jwsSignerFactory.createJWSSigner(this.jwk);
				signedJwt.sign(signer);
				return signedJwt;
			}
			catch (Exception ex) {
				throw new JwtEncodingException(
						String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to sign the JWT"), ex);
			}
		}
	}

	static final class NimbusJwsHeaderMutator implements JwsHeaderMutator<NimbusJwsHeaderMutator> {
		private final Map<String, Object> headers = new LinkedHashMap<>();
		private final Map<String, Object> criticalHeaders = new LinkedHashMap<>();

		@Override
		public NimbusJwsHeaderMutator algorithm(JwsAlgorithm jws) {
			return header(JoseHeaderNames.ALG, jws.getName());
		}

		@Override
		public NimbusJwsHeaderMutator criticalHeaders(Consumer<Map<String, Object>> criticalHeadersConsumer) {
			criticalHeadersConsumer.accept(this.criticalHeaders);
			return this;
		}

		@Override
		public NimbusJwsHeaderMutator headers(Consumer<Map<String, Object>> headersConsumer) {
			headersConsumer.accept(this.headers);
			return this;
		}

		JWSHeader jwsHeader() {
			Map<String, Object> allHeaders = new LinkedHashMap<>(this.headers);
			if (!this.criticalHeaders.isEmpty()) {
				allHeaders.put(JoseHeaderNames.CRIT, this.criticalHeaders.keySet());
				allHeaders.putAll(this.criticalHeaders);
			}

			try {
				return JWSHeader.parse(allHeaders);
			} catch (Exception ex) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
						"Failed to convert header to Nimbus JWSHeader"), ex);
			}
		}
	}

	static final class NimbusJwtClaimMutator implements JwtClaimMutator<NimbusJwtClaimMutator> {
		private final Map<String, Object> claims = new LinkedHashMap<>();

		@Override
		public NimbusJwtClaimMutator claim(String name, Object value) {
			if (value instanceof Instant) {
				return claim(name, ((Instant) value).getEpochSecond());
			}
			return claims((headers) -> headers.put(name, value));
		}

		@Override
		public NimbusJwtClaimMutator claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		JWTClaimsSet jwtClaimsSet() {
			try {
				return JWTClaimsSet.parse(this.claims);
			} catch (Exception ex) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
						"Failed to convert claims to Nimbus JWTClaimsSet"), ex);
			}
		}
	}
}
