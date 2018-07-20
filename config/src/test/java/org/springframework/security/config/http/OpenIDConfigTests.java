/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.http;

import java.util.HashSet;
import java.util.Set;
import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.openid.OpenIDConsumer;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests usage of the &lt;openid-login&gt; element
 *
 * @author Luke Taylor
 */
public class OpenIDConfigTests {
	private static final String CONFIG_LOCATION_PREFIX =
			"classpath:org/springframework/security/config/http/OpenIDConfigTests";

	@Autowired
	MockMvc mvc;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	public void requestWhenOpenIDAndFormLoginBothConfiguredThenRedirectsToGeneratedLoginPage()
			throws Exception {

		this.spring.configLocations(this.xml("WithFormLogin")).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));

		assertThat(getFilter(DefaultLoginPageGeneratingFilter.class)).isNotNull();
	}

	@Test
	public void requestWhenOpenIDAndFormLoginWithFormLoginPageConfiguredThenFormLoginPageWins()
			throws Exception {

		this.spring.configLocations(this.xml("WithFormLoginPage")).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/form-page"));
	}

	@Test
	public void requestWhenOpenIDAndFormLoginWithOpenIDLoginPageConfiguredThenOpenIDLoginPageWins()
			throws Exception {

		this.spring.configLocations(this.xml("WithOpenIDLoginPageAndFormLogin")).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/openid-page"));
	}

	@Test
	public void configureWhenOpenIDAndFormLoginBothConfigureLoginPagesThenWiringException()
			throws Exception {

		assertThatCode(() -> this.spring.configLocations(this.xml("WithFormLoginAndOpenIDLoginPages")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void requestWhenOpenIDAndRememberMeConfiguredThenRememberMePassedToIdp()
			throws Exception {

		this.spring.configLocations(this.xml("WithRememberMe")).autowire();

		OpenIDAuthenticationFilter openIDFilter = getFilter(OpenIDAuthenticationFilter.class);

		String openIdEndpointUrl = "http://testopenid.com?openid.return_to=";
		Set<String> returnToUrlParameters = new HashSet<>();
		returnToUrlParameters.add(AbstractRememberMeServices.DEFAULT_PARAMETER);
		openIDFilter.setReturnToUrlParameters(returnToUrlParameters);

		OpenIDConsumer consumer = mock(OpenIDConsumer.class);
		when(consumer.beginConsumption(any(HttpServletRequest.class), anyString(), anyString(), anyString()))
				.then(invocation -> openIdEndpointUrl + invocation.getArgument(2));
		openIDFilter.setConsumer(consumer);

		String expectedReturnTo = new StringBuilder("http://localhost/login/openid").append("?")
				.append(AbstractRememberMeServices.DEFAULT_PARAMETER)
				.append("=").append("on").toString();

		this.mvc.perform(get("/"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));

		this.mvc.perform(get("/login"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString(AbstractRememberMeServices.DEFAULT_PARAMETER)));

		this.mvc.perform(get("/login/openid")
				.param(OpenIDAuthenticationFilter.DEFAULT_CLAIMED_IDENTITY_FIELD, "http://hey.openid.com/")
				.param(AbstractRememberMeServices.DEFAULT_PARAMETER, "on"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl(openIdEndpointUrl + expectedReturnTo));
	}

	@Test
	public void requestWhenAttributeExchangeConfiguredThenFetchAttributesPassedToIdp()
			throws Exception {

		this.spring.configLocations(this.xml("WithOpenIDAttributes")).autowire();

		try ( MockWebServer server = new MockWebServer() ) {
			server.enqueue(new MockResponse().setBody("body"));

			MvcResult result =
					this.mvc.perform(get("/login/openid")
							.param(OpenIDAuthenticationFilter.DEFAULT_CLAIMED_IDENTITY_FIELD, "http://localhost:9090/")
							.param(AbstractRememberMeServices.DEFAULT_PARAMETER, "on"))
							.andExpect(status().isFound())
							.andExpect(redirectedUrl("blah"))
							.andReturn();
		}
	}

	@Test
	public void requestWhenLoginPageConfiguredWithPhraseLoginThenRedirectsOnlyToUserGeneratedLoginPage() {

	}

	@RestController
	static class BasicController {
		@GetMapping("/form-page")
		public String first() {
			return "form";
		}

		@GetMapping("/openid-page")
		public String openidLogin() {
			return "openid";
		}
	}

	private <T extends Filter> T getFilter(Class<T> clazz) {
		FilterChainProxy filterChain = this.spring.getContext().getBean(FilterChainProxy.class);
		return (T)filterChain.getFilters("/").stream()
				.filter(clazz::isInstance)
				.findFirst()
				.orElse(null);
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	/*
	def openIDWithAttributeExchangeConfigurationIsParsedCorrectly() {
		xml.http() {
			'openid-login'() {
				'attribute-exchange'() {
					'openid-attribute'(name: 'nickname', type: 'http://schema.openid.net/namePerson/friendly')
					'openid-attribute'(name: 'email', type: 'http://schema.openid.net/contact/email', required: 'true',
							'count': '2')
				}
			}
		}
		createAppContext()

		List attributes = getFilter(OpenIDAuthenticationFilter).consumer.attributesToFetchFactory.createAttributeList('http://someid')

		expect:
		attributes.size() == 2
		attributes[0].name == 'nickname'
		attributes[0].type == 'http://schema.openid.net/namePerson/friendly'
		!attributes[0].required
		attributes[1].required
		attributes[1].getCount() == 2
	}

	def 'SEC-2919: DefaultLoginGeneratingFilter should not be present if login-page="/login"'() {
		when:
		xml.http() {
			'openid-login'('login-page':'/login')
		}
		createAppContext()

		then:
		getFilter(DefaultLoginPageGeneratingFilter) == null
	}
*/
}
