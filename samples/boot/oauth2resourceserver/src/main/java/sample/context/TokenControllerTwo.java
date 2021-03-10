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

package sample.context;

import java.util.Map;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.JwsHeaderMutator;
import org.springframework.security.oauth2.jwt.JwtClaimMutator;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenControllerTwo {
	@Autowired
	NimbusJwtEncoder jwtEncoder;

	@Autowired
	Consumer<JwsHeaderMutator<?>> headerMutator;

	@Autowired
	Consumer<JwtClaimMutator<?>> claimsMutator;

	@GetMapping("/token/two")
	String tokenTwo() {
		return this.jwtEncoder.encoder()
				.jwsHeaders(this.headerMutator)
				.jwsHeaders((headers) -> headers.criticalHeaders(Map::clear))
				.jwsSecurityContext(new TenantSecurityContext("subdomain"))
				.claims(this.claimsMutator)
				.claims((claims) -> claims.id("id"))
				.encode();
	}


	/**
	 * What's nice about this pattern is that it's minimal for the application.
	 * For example, note that because of the application configuration, I only
	 * need one Spring Security component to sign and serialize a JWT.
	 */
	@GetMapping("/token/two/simple")
	String tokenTwoSimple() {
		return this.jwtEncoder.encoder().encode();
	}
}
