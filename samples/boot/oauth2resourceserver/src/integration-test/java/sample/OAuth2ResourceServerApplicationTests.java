/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.bearerToken;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class OAuth2ResourceServerApplicationTests {

	ClassPathResource noScopesToken = new ClassPathResource("no.scope");
	ClassPathResource messageReadToken = new ClassPathResource("message-read.scope");

	@Autowired
	MockMvc mvc;

	@Test
	public void performWhenValidBearerTokenThenAllows()
		throws Exception {

		this.mvc.perform(get("/").with(bearerToken(this.noScopesToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Hello")));
	}

	@Test
	public void performWhenValidBearerTokenThenNoSessionCreated()
			throws Exception {

		MvcResult result =
				this.mvc.perform(get("/").with(bearerToken(this.noScopesToken)))
						.andReturn();

		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void performWhenMalformedBearerTokenThenUnauthorized()
			throws Exception {

		this.mvc.perform(get("/").with(bearerToken("malformed")))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
						containsString("Bearer error=\"invalid_token\", " +
								"error_description=\"An error occurred while attempting to decode the Jwt: " +
								"Invalid JWT serialization: Missing dot delimiter(s)\"")));
	}

	// -- tests with scopes

	@Test
	public void performWhenValidBearerTokenThenScopedMethodsAlsoWork()
			throws Exception {

		this.mvc.perform(get("/message").with(bearerToken(this.messageReadToken)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("secret message")));
	}

	@Test
	public void performWhenInsufficientlyScopedBearerTokenThenDeniesScopedMethodAccess()
			throws Exception {

		this.mvc.perform(get("/denyAll").with(bearerToken(this.messageReadToken)))
				.andExpect(status().isForbidden())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
						containsString("Bearer error=\"insufficient_scope\", " +
								"error_description=\"The token provided has insufficient scope [message:read] for this request\", " +
								"error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\", " +
								"scope=\"message:read\"")));
	}
}
