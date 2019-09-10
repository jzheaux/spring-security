/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.config.annotation.web.configuration;

import java.net.URI;

import org.junit.Rule;
import org.junit.Test;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.web.reactive.function.client.MockExchangeFunction;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.web.reactive.function.client.ServletBearerExchangeFilterFunction;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.ClientRequest;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.security.oauth2.server.resource.authentication.TestBearerTokenAuthentications.bearer;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link OAuth2ResourceServerConfiguration}.
 *
 * @author Josh Cummings
 */
public class OAuth2ResourceServerConfigurationTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	// gh-7418
	@Test
	public void requestWhenAuthenticatedThenBearerTokenPropagated() throws Exception {
		BearerTokenAuthentication authentication = bearer();
		this.spring.register(BearerWebClientConfig.class).autowire();

		this.mockMvc.perform(get("/token")
				.with(authentication(authentication)))
				.andExpect(status().isOk())
				.andExpect(content().string("Bearer token"));
	}


	@EnableWebSecurity
	static class BearerWebClientConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
		}

		@RestController
		public class Controller {

			@GetMapping("/token")
			public String message() {
				ServletBearerExchangeFilterFunction bearer = new ServletBearerExchangeFilterFunction();
				ClientRequest request =
						ClientRequest.create(GET, URI.create("https://example.org")).build();
				MockExchangeFunction exchange = new MockExchangeFunction();
				Flux.concat(bearer.filter(request, exchange))
					.subscribeOn(Schedulers.elastic())
					.collectList().block();
				return exchange.getRequest().headers().getFirst(AUTHORIZATION);
			}
		}
	}
}
