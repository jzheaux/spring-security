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
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;

public class NimbusJwtEncoder implements JwtEncoderAlternative {
	private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

	private JwsAlgorithm defaultAlgorithm = SignatureAlgorithm.RS256;
	private JWKSource<SecurityContext> jwksSource;

	public void setJwkSource(JWKSource<SecurityContext> jwksSource) {
		Assert.notNull(jwksSource, "jwkSelector cannot be null");
		this.jwksSource = jwksSource;
	}

	/**
	 * While true that a new {@link NimbusJwtSpec} is created on every invocation,
	 * such is no more work than is already being asked of the JVM in the original PR
	 * which requires two objects to be constructed {@link JoseHeader} and {@link JwtClaimsSet}
	 * in order to call it.
	 *
	 * There was originally a question about thread-safety, but there is no less thread-safety
	 * here than with the {@link JoseHeader} and {@link JwtClaimsSet} builders.
	 *
	 * Also note that this implementation specifies the {@code iat}, {@code exp}, and {@code nbf}
	 * claims. I add these for illustration of the fact that, when following this pattern it's
	 * simple for each implementation to supply reasonable defaults. Spring Security's
	 * reasonable defaults will likely be much more conservative than a given company's reasonable
	 * defaults, but the point is that this allows a company implementing custom Spring Security
	 * components to offer their own opinion in the same place in the codebase where we offer ours.
	 *
	 * This is not mixing concerns, it is simply asking for the method parameters in a
	 * way that allows the caller to override the opinion of this implementation. With
	 * that kind of a construct, it's very simple for implementers to base their custom
	 * implementation off of this one. This is a more secure way for a platform team at a company
	 * to set important defaults without getting in the way of application developers who have
	 * legitimate exceptions.
	 *
	 * Finally, this class could potentially be renamed and internally could invoke
	 * the proposed {@link JwtEncoder}. The limiting factor there is that this class allows the
	 * caller access to the underlying Nimbus library, and it would be tricky to hand that context down
	 * through {@link JwtEncoder}. Since this class is Nimbus-specific anyway, I see no
	 * reason to call an abstracted version of Nimbus's JWT minting support.
	 */
	@Override
	public NimbusJwtSpec encoder() {
		Instant now = Instant.now();
		return new NimbusJwtSpec(this.jwksSource)
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

	public static final class NimbusJwtSpec implements JwtMutator<NimbusJwtSpec> {
		private final JWSSignerFactory jwsSignerFactory = new DefaultJWSSignerFactory();
		private final JWKSource<SecurityContext> jwkSource;
		private final NimbusJwtClaimMutator claims = new NimbusJwtClaimMutator();
		private final NimbusJwsHeaderMutator jwsHeaders = new NimbusJwsHeaderMutator();

		private JWK jwk;
		private SecurityContext context;

		private NimbusJwtSpec(JWKSource<SecurityContext> jwkSource) {
			this.jwkSource = jwkSource;
		}

		@Override
		public NimbusJwtSpec jwsHeaders(Consumer<JwsHeaderMutator<?>> headersConsumer) {
			headersConsumer.accept(this.jwsHeaders);
			return this;
		}

		/**
		 * This is intended to demonstrate that this pattern simplifies exposing
		 * library-specific domain objects that we don't want to replicate in Spring
		 * Security, like JWK.
		 *
		 * Actually, I think this method might be unnecessary since with {@link #jwsSecurityContext}
		 * the caller could specify a {@link com.nimbusds.jose.proc.JWKSecurityContext}. But
		 * I've left it in here for demonstration.
		 */
		public NimbusJwtSpec jwsKey(JWK jwk) {
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
		 * This is intended to demonstrate the power of exposing library-specific
		 * domain objects at the method-invocation level. Since Nimbus takes a {@link SecurityContext}
		 * as a method parameter, an API that also accepts it as a method parameter
		 * will have the least impedence mismatch.
		 */
		public NimbusJwtSpec jwsSecurityContext(SecurityContext context) {
			this.context = context;
			return this;
		}

		@Override
		public NimbusJwtSpec claims(Consumer<JwtClaimMutator<?>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		@Override
		public String encode() {
			if (this.jwk == null) {
				jwsKey(selectJwk());
			}
			return sign().serialize();
		}

		/**
		 * As a side note, this method can be removed once Nimbus adds a JWT minting component
		 */
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

		/**
		 * As a side note, this method can be removed once Nimbus adds a JWT minting component
		 */
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

	/**
	 * I think it's reasonable to have this delegate to a domain object where some of this
	 * behavior is centralized. For example, {@link JoseHeader.Builder} could contain the extra support for
	 * critical headers so that the Nimbus implementation doesn't need to have it as well.
	 *
	 * Note as well that this conversion needs to happen with either approach.
	 * I prefer this approach because it reduces business logic, like checking whether a value exists
	 * before converting it.
	 */
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

	/**
	 * Note as well that this conversion needs to happen with either approach.
	 * I prefer this approach because it reduces business logic, like checking whether a value exists
	 * before converting it.
	 */
	static final class NimbusJwtClaimMutator implements JwtClaimMutator<NimbusJwtClaimMutator> {
		private final Map<String, Object> claims = new LinkedHashMap<>();

		/**
		 * {@link Instant} is the only datatype that I know of that Nimbus does not
		 * know how to parse for us in {@link JWTClaimsSet#parse}. Everything else,
		 * we can simply lean on Nimbus to do the work.
		 */
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
