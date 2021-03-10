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

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.security.oauth2.jose.jws.EncryptionAlgorithm;
import org.springframework.security.oauth2.jose.jws.EncryptionMethod;
import org.springframework.security.oauth2.jose.jws.JweAlgorithm;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;

/**
 * Signs and serialized a JWT using the Nimbus library
 */
public class NimbusJwtEncoder implements JwtEncoderAlternative {
	private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

	private JwsAlgorithm defaultAlgorithm = SignatureAlgorithm.RS256;
	private JweAlgorithm defaultJweAlgorithm = EncryptionAlgorithm.RSA_OAEP_256;
	private EncryptionMethod defaultEncryptionMethod = EncryptionMethod.A256GCM;

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
				.jweHeaders((jwe) -> jwe
						.algorithm(this.defaultJweAlgorithm)
						.encryptionMethod(this.defaultEncryptionMethod)
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
		private final NimbusJweHeaderMutator jweHeaders = new NimbusJweHeaderMutator();

		private JWK jwsKey;
		private JWK jweKey;
		private SecurityContext jwsContext;
		private SecurityContext jweContext;

		private NimbusJwtMutator(JWKSource<SecurityContext> jwkSource) {
			this.jwkSource = jwkSource;
		}

		@Override
		public NimbusJwtMutator jwsHeaders(Consumer<JwsHeaderMutator<?>> headersConsumer) {
			headersConsumer.accept(this.jwsHeaders);
			return this;
		}

		@Override
		public NimbusJwtMutator jweHeaders(Consumer<JweHeaderMutator<?>> headersConsumer) {
			headersConsumer.accept(this.jweHeaders);
			return this;
		}

		/**
		 * Use this {@link JWK} to sign the JWT
		 */
		public NimbusJwtMutator jwsKey(JWK jwk) {
			this.jwsKey = jwk;
			if (this.jwsKey.getKeyID() != null) {
				this.jwsHeaders.headers.put(JoseHeaderNames.KID, this.jwsKey.getKeyID());
			}
			if (this.jwsKey.getX509CertSHA256Thumbprint() != null) {
				this.jwsHeaders.headers.put(JoseHeaderNames.X5T, this.jwsKey.getX509CertSHA256Thumbprint().toString());
			}
			return this;
		}

		/**
		 * Use this {@link JWK} to encrypt the JWT
		 */
		public NimbusJwtMutator jweKey(RSAKey jwk) {
			this.jweKey = jwk;
			if (this.jweKey.getKeyID() != null) {
				this.jweHeaders.headers.put(JoseHeaderNames.KID, this.jweKey.getKeyID());
			}
			if (this.jweKey.getX509CertSHA256Thumbprint() != null) {
				this.jweHeaders.headers.put(JoseHeaderNames.X5T, this.jweKey.getX509CertSHA256Thumbprint().toString());
			}
			return this;
		}

		/**
		 * Send this {@link SecurityContext} to Nimbus's signing infrastructure
		 */
		public NimbusJwtMutator jwsSecurityContext(SecurityContext context) {
			this.jwsContext = context;
			return this;
		}

		/**
		 * Send this {@link SecurityContext} to Nimbus's encryption infrastructure
		 */
		public NimbusJwtMutator jweSecurityContext(SecurityContext context) {
			this.jweContext = context;
			return this;
		}

		@Override
		public NimbusJwtMutator claims(Consumer<JwtClaimMutator<?>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		@Override
		public String encode() {
			return encode(EncodingMode.SIGN);
		}

		@Override
		public String encode(EncodingMode mode) {
			switch (mode) {
				case SIGN: return sign();
				case ENCRYPT: return encrypt(false);
				default: return encrypt(true);
			}
		}

		private String sign() {
			if (this.jwsKey == null) {
				if (this.jwsContext instanceof JWKSecurityContext) {
					this.jwsKey = ((JWKSecurityContext) this.jwsContext).getKeys().iterator().next();
				} else if (this.jwkSource != null) {
					jwsKey(selectJwsJwk());
				} else {
					throw new IllegalStateException("Could not derive a signing key");
				}
			}

			JWSHeader jwsHeader = this.jwsHeaders.jwsHeader();
			JWTClaimsSet jwtClaimsSet = this.claims.jwtClaimsSet();

			SignedJWT signedJwt = new SignedJWT(jwsHeader, jwtClaimsSet);
			try {
				JWSSigner signer = this.jwsSignerFactory.createJWSSigner(this.jwsKey);
				signedJwt.sign(signer);
				return signedJwt.serialize();
			}
			catch (Exception ex) {
				throw new JwtEncodingException(
						String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to sign the JWT"), ex);
			}
		}

		private String encrypt(boolean sign) {
			if (sign) {
				this.jweHeaders.header(JoseHeaderNames.CTY, "JWT"); // required parameter
				return encrypt(new Payload(sign()));
			} else {
				return encrypt(new Payload(this.claims.jwtClaimsSet().toJSONObject()));
			}
		}

		private JWK selectJwsJwk() {
			List<JWK> jwks;
			try {
				JWSHeader jwsHeader = this.jwsHeaders.jwsHeader();
				JWKSelector jwkSelector = new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader));
				jwks = this.jwkSource.get(jwkSelector, this.jwsContext);
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

		private JWK selectJweJwk() {
			List<JWK> jwks;
			try {
				JWEHeader jweHeader = this.jweHeaders.jweHeader();
				JWKSelector jwkSelector = new JWKSelector(JWKMatcher.forJWEHeader(jweHeader));
				jwks = this.jwkSource.get(jwkSelector, this.jweContext);
			}
			catch (Exception ex) {
				throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
						"Failed to select a JWK encryption key -> " + ex.getMessage()), ex);
			}

			if (jwks.isEmpty()) {
				throw new JwtEncodingException(
						String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to select a JWK encryption key"));
			}

			return jwks.get(0);
		}

		private String encrypt(Payload payload) {
			if (this.jweKey == null) {
				if (this.jweContext instanceof JWKSecurityContext) {
					this.jweKey = ((JWKSecurityContext) this.jweContext).getKeys().iterator().next();
				} else if (this.jwkSource != null) {
					jweKey((RSAKey) selectJweJwk());
				} else {
					throw new IllegalStateException("Could not derive a encryption key");
				}
			}

			JWEHeader jweHeader = this.jweHeaders.jweHeader();
			JWEObject object = new JWEObject(jweHeader, payload);
			try {
				object.encrypt(new RSAEncrypter((RSAKey) this.jweKey));
				return object.serialize();
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

	static final class NimbusJweHeaderMutator implements JweHeaderMutator<NimbusJweHeaderMutator> {
		private final Map<String, Object> headers = new LinkedHashMap<>();
		private final Map<String, Object> criticalHeaders = new LinkedHashMap<>();

		@Override
		public NimbusJweHeaderMutator algorithm(JweAlgorithm jwe) {
			return header(JoseHeaderNames.ALG, jwe.getName());
		}

		@Override
		public NimbusJweHeaderMutator encryptionMethod(EncryptionMethod method) {
			return header("enc", method.getName());
		}

		@Override
		public NimbusJweHeaderMutator criticalHeaders(Consumer<Map<String, Object>> criticalHeadersConsumer) {
			criticalHeadersConsumer.accept(this.criticalHeaders);
			return this;
		}

		@Override
		public NimbusJweHeaderMutator headers(Consumer<Map<String, Object>> headersConsumer) {
			headersConsumer.accept(this.headers);
			return this;
		}

		JWEHeader jweHeader() {
			Map<String, Object> allHeaders = new LinkedHashMap<>(this.headers);
			if (!this.criticalHeaders.isEmpty()) {
				allHeaders.put(JoseHeaderNames.CRIT, this.criticalHeaders.keySet());
				allHeaders.putAll(this.criticalHeaders);
			}

			try {
				return JWEHeader.parse(allHeaders);
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
