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

import java.util.Map;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.JwsHeaderMutator;
import org.springframework.security.oauth2.jwt.JwtClaimMutator;
import org.springframework.security.oauth2.jwt.JwtEncoderAlternative;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenControllerTwo {
	@Autowired
	JwtEncoderAlternative jwtEncoder;

	@Autowired
	Consumer<JwsHeaderMutator<?>> defaultHeader;

	@Autowired
	Consumer<JwtClaimMutator<?>> defaultClaimsSet;

	/**
	 * This method is intended to demonstrate that both coding styles are possible with
	 * {@link JwtEncoderAlternative}, though I'll point out that this is less
	 * preferred due to the number of Spring Security components involved.
	 *
	 * In Authorization Server, there is an additional proposal for a separate customizer class,
	 * which could mean that folks may need to have four components to encode a JWT:
	 *
	 * 1. Use the customizer to create
	 * 2. A header object, and
	 * 3. A claims object, and then
	 * 4. Pass those two objects into encode
	 *
	 * If you take a look at {@link sample.singlekey.TokenControllerTwo#tokenTwoSimple()}, only one component
	 * is required to get all the benefit, which I think is quite nice for the application developer.
	 */
	@GetMapping("/token/two")
	String tokenTwo() {
		return this.jwtEncoder.encoder()
				.jwsHeaders(this.defaultHeader)
				.jwsHeaders((headers) -> headers.criticalHeaders(Map::clear))
				.claims(this.defaultClaimsSet)
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
