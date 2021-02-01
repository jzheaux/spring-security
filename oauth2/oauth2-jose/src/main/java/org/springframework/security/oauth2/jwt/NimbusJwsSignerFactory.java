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

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.mint.JWSMinter;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.Assert;

/**
 * A factory for signing JWS payloads
 */
public class NimbusJwsSignerFactory implements JwsSignerFactory {

	private final JWSMinter<SecurityContext> minter;

	private Clock clock = Clock.systemUTC();

	private Consumer<SigningSpec<?>> jwtCustomizer = (spec) -> {
	};

	/**
	 * Construct a {@link NimbusJwsSignerFactory} using the provided parameters
	 * @param minter the source for looking up the appropriate signing JWK
	 */
	public NimbusJwsSignerFactory(JWSMinter<SecurityContext> minter) {
		Assert.notNull(minter, "minter cannot be null");
		this.minter = minter;
	}

	@Override
	public SigningSpec<?> signer() {
		Instant now = Instant.now(this.clock);
		return new NimbusEncoderSpec(this.minter).algorithm(SignatureAlgorithm.RS256).type("JWT")
				.jti(UUID.randomUUID().toString()).issuedAt(now).expiresAt(now.plusSeconds(3600))
				.apply(this.jwtCustomizer);
	}

	/**
	 * Set an application-level customizer for overriding claims and headers before
	 * signing.
	 * @param jwtCustomizer
	 */
	public void setJwtCustomizer(Consumer<SigningSpec<?>> jwtCustomizer) {
		this.jwtCustomizer = jwtCustomizer;
	}

	/**
	 * Set the {@link Clock} to use, mostly to simplify testing
	 * @param clock
	 */
	public void setClock(Clock clock) {
		this.clock = clock;
	}

	private static final class NimbusEncoderSpec extends Jwt.JwtSpecSupport<NimbusEncoderSpec>
			implements SigningSpec<NimbusEncoderSpec> {

		private final JWSMinter<SecurityContext> minter;

		private NimbusEncoderSpec(JWSMinter<SecurityContext> minter) {
			this.minter = minter;
		}

		NimbusEncoderSpec apply(Consumer<SigningSpec<?>> specConsumer) {
			specConsumer.accept(this);
			return this;
		}

		@Override
		public Jwt sign() {
			// consider using ConfigurableJWTMinter in Nimbus
			SignedJWT jwt = signedJwt();
			JWSHeader header = jwt.getHeader();
			return Jwt.withTokenValue(jwt.serialize())
					.headers((headers) -> headers.putAll(header.toJSONObject()))
					.claims((claims) -> claims.putAll(this.claims))
					.build();
		}

		private SignedJWT signedJwt() {
			try {
				return this.minter.mint(jwsHeader(this.headers), jwtClaimSet(this.claims), null);
			} catch (Exception e) {
				throw new JwtEncodingException("Failed to sign JWT", e);
			}
		}

		private JWSHeader jwsHeader(Map<String, Object> headers) {
			try {
				return JWSHeader.parse(headers);
			}
			catch (Exception e) {
				throw new JwtEncodingException("Failed to read JWS header", e);
			}
		}

		private JWTClaimsSet jwtClaimSet(Map<String, Object> claims) {
			Map<String, Object> datesConverted = new HashMap<>(claims);
			datesConverted.replaceAll((key, value) -> {
				if (value instanceof Instant) {
					return ((Instant) value).getEpochSecond();
				}
				return value;
			});
			try {
				return JWTClaimsSet.parse(datesConverted);
			}
			catch (Exception e) {
				throw new JwtEncodingException("Failed to read claims", e);
			}
		}

	}

}
