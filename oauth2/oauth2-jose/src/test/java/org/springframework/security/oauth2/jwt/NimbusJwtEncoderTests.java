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

import java.util.Arrays;
import java.util.function.Consumer;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtEncoderAlternative.EncodingMode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link NimbusJwsEncoder}.
 *
 * @author Joe Grandja
 */
public class NimbusJwtEncoderTests {

	private JWKSource<SecurityContext> jwkSelector;

	private NimbusJwtEncoder jwsEncoder;

	@Before
	public void setUp() {
		this.jwkSelector = mock(JWKSource.class);
		this.jwsEncoder = new NimbusJwtEncoder();
		this.jwsEncoder.setJwkSource(this.jwkSelector);
	}

	@Test
	public void constructorWhenJwkSelectorNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.jwsEncoder.setJwkSource(null))
				.withMessage("jwkSelector cannot be null");
	}

	@Test
	public void encodeWhenJwkNotSelectedThenThrowJwtEncodingException() {
		assertThatExceptionOfType(JwtEncodingException.class).isThrownBy(() -> this.jwsEncoder.encoder().encode())
				.withMessageContaining("Failed to select a JWK signing key");
	}

	@Test
	public void encodeWhenJwkUseEncryptionThenThrowJwtEncodingException() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.keyUse(KeyUse.ENCRYPTION)
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		assertThatExceptionOfType(JwtEncodingException.class).isThrownBy(() -> this.jwsEncoder.encoder().encode())
				.withMessageContaining(
						"Failed to sign the JWT");
	}

	@Test
	public void encodeWhenSuccessThenDecodes() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		String token = this.jwsEncoder.encoder().claims((claims) -> claims.id("id")).encode();
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		Jwt jwt = jwtDecoder.decode(token);

		// Assert headers/claims were added
		assertThat(jwt.getHeaders().get(JoseHeaderNames.TYP)).isEqualTo("JWT");
		assertThat(jwt.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(rsaJwk.getKeyID());
		assertThat(jwt.getId()).isNotNull();
	}

	@Test
	public void encodeWhenCustomizerSetThenCalled() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		Consumer<JwtClaimMutator<?>> jwtCustomizer = mock(Consumer.class);
		JwtEncoderAlternative encoder = () -> this.jwsEncoder.encoder().claims(jwtCustomizer);
		encoder.encoder().encode();

		verify(jwtCustomizer).accept(any(JwtClaimMutator.class));
	}

	@Test
	public void defaultJwkSelectorApplyWhenMultipleSelectedThenThrowJwtEncodingException() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk, rsaJwk));

		assertThatExceptionOfType(JwtEncodingException.class).isThrownBy(() -> this.jwsEncoder.encoder().encode())
				.withMessageContaining("Found multiple JWK signing keys for algorithm 'RS256'");
	}

	@Test
	public void encodeWhenKeysRotatedThenNewKeyUsed() throws Exception {
		// @formatter:off
		RSAKey first = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("first")
				.build();
		RSAKey second = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("second")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(first));

		String firstToken = this.jwsEncoder.encoder().encode();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey((first).toRSAPublicKey()).build();
		Jwt firstDecoded = jwtDecoder.decode(firstToken);

		reset(this.jwkSelector);
		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(second));

		String secondToken = this.jwsEncoder.encoder().encode();

		jwtDecoder = NimbusJwtDecoder.withPublicKey((second).toRSAPublicKey()).build();
		Jwt secondDecoded = jwtDecoder.decode(secondToken);

		assertThat(firstDecoded.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(first.getKeyID());
		assertThat(secondDecoded.getHeaders().get(JoseHeaderNames.KID)).isEqualTo(second.getKeyID());
	}

	@Test
	public void encodeWhenClaimsThenContains() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		String token = this.jwsEncoder.encoder().claims((claims) -> claims.subject("subject")).encode();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		Jwt decoded = jwtDecoder.decode(token);

		assertThat(decoded.getSubject()).isEqualTo("subject");
	}

	@Test
	public void encodeWhenDefaultClaimRemovedThenRemoved() throws Exception {
		// @formatter:off
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();
		// @formatter:on

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		String token = this.jwsEncoder.encoder()
				.claims((claims) -> claims
						.subject("subject")
						.claims((map) -> map.remove("exp")))
						.encode();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		Jwt decoded = jwtDecoder.decode(token);

		assertThat(decoded.getExpiresAt()).isNull();
	}

	@Test
	public void encryptWithDefaultsThenWorks() throws Exception {
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.keyUse(KeyUse.ENCRYPTION)
				.build();

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		String token = this.jwsEncoder.encoder().encode(EncodingMode.ENCRYPT);

		DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWEKeySelector(new JWEDecryptionKeySelector<>(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, new ImmutableJWKSet<>(new JWKSet(rsaJwk))));
		JWTClaimsSet claims = processor.process(token, null);
		assertThat(claims.getExpirationTime()).isNotNull();
	}

	@Test
	public void signThenEncryptWithDefaultsThenWorks() throws Exception {
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		String token = this.jwsEncoder.encoder().encode(EncodingMode.SIGN_THEN_ENCRYPT);

		DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWEKeySelector(new JWEDecryptionKeySelector<>(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, new ImmutableJWKSet<>(new JWKSet(rsaJwk))));
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new ImmutableJWKSet<>(new JWKSet(rsaJwk))));
		JWTClaimsSet claims = processor.process(token, null);
		assertThat(claims.getExpirationTime()).isNotNull();
	}

	@Test
	public void signThenEncryptWithOverridingClaimsThenWorks() throws Exception {
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		String token = this.jwsEncoder.encoder()
				.jwsHeaders((jws) -> jws.algorithm(SignatureAlgorithm.RS512))
				.jweHeaders((jwe) -> jwe.header("zip", "DEF"))
				.claims((claims) -> claims.id("id"))
				.encode(EncodingMode.SIGN_THEN_ENCRYPT);

		DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWEKeySelector(new JWEDecryptionKeySelector<>(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, new ImmutableJWKSet<>(new JWKSet(rsaJwk))));
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS512, new ImmutableJWKSet<>(new JWKSet(rsaJwk))));
		JWTClaimsSet claims = processor.process(token, null);
		assertThat(claims.getJWTID()).isEqualTo("id");
		assertThat(claims.getExpirationTime()).isNotNull();
	}

	@Test
	public void signWithSettingKeyThenWorks() throws Exception {
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		String token = this.jwsEncoder.encoder().jwsKey(rsaJwk).encode();

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaJwk.toRSAPublicKey()).build();
		Jwt decoded = jwtDecoder.decode(token);
		assertThat(decoded.getHeaders().get(JoseHeaderNames.KID)).isEqualTo("keyId");
		assertThat(decoded.getExpiresAt()).isNotNull();
	}

	@Test
	public void encryptWithSettingKeyThenWorks() throws Exception {
		RSAKey rsaJwk = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY)
				.privateKey(TestKeys.DEFAULT_PRIVATE_KEY)
				.keyID("keyId")
				.build();

		given(this.jwkSelector.get(any(), any())).willReturn(Arrays.asList(rsaJwk));

		String token = this.jwsEncoder.encoder().jweKey(rsaJwk).encode(EncodingMode.ENCRYPT);

		DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWEKeySelector(new JWEDecryptionKeySelector<>(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, new ImmutableJWKSet<>(new JWKSet(rsaJwk))));
		JWTClaimsSet claims = processor.process(token, null);
		assertThat(claims.getExpirationTime()).isNotNull();
	}
}
