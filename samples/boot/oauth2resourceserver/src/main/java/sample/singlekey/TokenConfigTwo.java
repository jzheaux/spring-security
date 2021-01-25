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

package sample.singlekey;

import java.time.Instant;

import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtEncoderAlternative;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
public class TokenConfigTwo {
	@Bean
	JwtEncoderAlternative jwsEncoder(RSAKey key) {
		NimbusJwtEncoder delegate = new NimbusJwtEncoder();
		return () -> delegate.encoder()
				.jwsKey(key) // simple to specify the key since I can expose Nimbus-specific methods when returning a builder
				.jwsHeaders((jws) -> jws.criticalHeader("exp", Instant.now())) // application-level opinion that might need overriding
				.claims((claims) -> claims
						.issuer("http://self")
						.subject(SecurityContextHolder.getContext().getAuthentication().getName())
				);
	}
}
