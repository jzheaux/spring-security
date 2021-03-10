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

package sample.style;

import java.time.Instant;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.JwsHeaderMutator;
import org.springframework.security.oauth2.jwt.JwtClaimMutator;
import org.springframework.security.oauth2.jwt.JwtEncoderAlternative;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
public class TokenConfigTwo {
	@Bean
	public Consumer<JwsHeaderMutator<?>> defaultHeader() {
		return (jws) -> jws
				.algorithm(SignatureAlgorithm.RS256)
				.header(JoseHeaderNames.TYP, "JWT")
				.criticalHeader("exp", Instant.now());  // application-level opinion that might need overriding
	}

	@Bean
	public Consumer<JwtClaimMutator<?>> defaultClaimsSet() {
		return (claims) -> claims
				.subject(SecurityContextHolder.getContext().getAuthentication().getName())
				.issuer("http://self");
	}

	@Bean
	JwtEncoderAlternative jwsEncoder(RSAKey key) {
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(key));
		NimbusJwtEncoder jwsEncoder = new NimbusJwtEncoder();
		jwsEncoder.setJwkSource(jwks);
		return jwsEncoder;
	}
}
