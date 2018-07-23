/*
 * Copyright 2002-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.http;

import javax.servlet.http.Cookie;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.TestDataSource;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl.CREATE_TABLE_SQL;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Oliver Becker
 */
public class RememberMeConfigTests {
	private static final String CONFIG_LOCATION_PREFIX =
			"classpath:org/springframework/security/config/http/RememberMeConfigTests";

	@Autowired
	MockMvc mvc;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	public void revisitWhenUsingRememberMeWithCustomTokenRepositoryThenAutomaticallyReauthenticates()
			throws Exception {

		this.spring.configLocations(this.xml("WithCustomTokenRepository")).autowire();

		MvcResult result =
				this.mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf()))
						.andExpect(redirectedUrl("/"))
						.andReturn();

		Cookie cookie = rememberMeCookie(result);

		assertThat(cookie.getSecure()).isFalse();

		this.mvc.perform(get("/authenticated")
				.cookie(cookie))
				.andExpect(status().isOk());

		JdbcTemplate template = this.spring.getContext().getBean(JdbcTemplate.class);
		int count = template.queryForObject("select count(*) from persistent_logins", int.class);
		assertThat(count).isEqualTo(1);
	}

	@Test
	public void revisitWhenUsingRememberMeWithCustomDataSourceThenAutomaticallyReauthenticates()
			throws Exception {

		this.spring.configLocations(this.xml("WithCustomDataSource")).autowire();

		TestDataSource dataSource = this.spring.getContext().getBean(TestDataSource.class);
		JdbcTemplate template = new JdbcTemplate(dataSource);
		template.execute(CREATE_TABLE_SQL);

		MvcResult result =
				this.mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf()))
						.andExpect(redirectedUrl("/"))
						.andReturn();

		Cookie cookie = rememberMeCookie(result);

		assertThat(cookie.getSecure()).isFalse();

		this.mvc.perform(get("/authenticated")
				.cookie(cookie))
				.andExpect(status().isOk());

		int count = template.queryForObject("select count(*) from persistent_logins", int.class);
		assertThat(count).isEqualTo(1);
	}

	@Test
	public void revisitWhenUsingRememberMeWithAuthenticationSuccessHandlerThenInvokesHandler()
			throws Exception {

		this.spring.configLocations(this.xml("WithAuthenticationSuccessHandler")).autowire();

		TestDataSource dataSource = this.spring.getContext().getBean(TestDataSource.class);
		JdbcTemplate template = new JdbcTemplate(dataSource);
		template.execute(CREATE_TABLE_SQL);

		MvcResult result =
				this.mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf()))
						.andExpect(redirectedUrl("/"))
						.andReturn();

		Cookie cookie = rememberMeCookie(result);

		assertThat(cookie.getSecure()).isFalse();

		this.mvc.perform(get("/authenticated")
				.cookie(cookie))
				.andExpect(redirectedUrl("/target"));

		int count = template.queryForObject("select count(*) from persistent_logins", int.class);
		assertThat(count).isEqualTo(1);
	}

	@Test
	public void revisitUsingRememberMeAndCustomRememberMeServicesThenAuthenticates()
			throws Exception {
		// SEC-1281 - using key with external services
		this.spring.configLocations(this.xml("WithServicesRef")).autowire();

		MvcResult result =
				this.mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf()))
						.andExpect(redirectedUrl("/"))
						.andReturn();

		Cookie cookie = rememberMeCookie(result);

		assertThat(cookie.getSecure()).isFalse();
		assertThat(cookie.getMaxAge()).isEqualTo(5000);

		this.mvc.perform(get("/authenticated")
				.cookie(cookie))
				.andExpect(status().isOk());

		// SEC-909
		result =
				this.mvc.perform(post("/logout")
						.cookie(cookie)
						.with(csrf()))
						.andReturn();

		cookie = rememberMeCookie(result);

		assertThat(cookie.getMaxAge()).isEqualTo(0);
	}

	@Test
	public void logoutWhenUsingRememberMeDefaultsThenCookieIsCancelled()
			throws Exception {
		this.spring.configLocations(this.xml("DefaultConfig")).autowire();

		MvcResult result =
				this.mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf()))
						.andExpect(redirectedUrl("/"))
						.andReturn();

		Cookie cookie = rememberMeCookie(result);

		result =
				this.mvc.perform(post("/logout")
						.cookie(cookie)
						.with(csrf()))
						.andReturn();

		cookie = rememberMeCookie(result);

		assertThat(cookie.getMaxAge()).isEqualTo(0);
	}

	@Test
	public void authenticateWithRememberMeWhenTokenValidityIsConfiguredThenCookieReflectsCorrectExpiration()
			throws Exception {

		this.spring.configLocations(this.xml("TokenValidity")).autowire();

		MvcResult result =
				this.mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf()))
						.andExpect(redirectedUrl("/"))
						.andReturn();

		Cookie cookie = rememberMeCookie(result);

		assertThat(cookie.getMaxAge()).isEqualTo(10000);

		this.mvc.perform(get("/authenticated")
				.cookie(cookie))
				.andExpect(status().isOk());
	}

	@Test
	public void authenticateWithRememberMeWhenTokenValidityIsNegativeThenCookieReflectsCorrectExpiration()
			throws Exception {

		this.spring.configLocations(this.xml("NegativeTokenValidity")).autowire();

		MvcResult result =
				this.mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf()))
						.andExpect(redirectedUrl("/"))
						.andReturn();

		Cookie cookie = rememberMeCookie(result);

		assertThat(cookie.getMaxAge()).isEqualTo(-1);
	}


	@Test
	public void configureWhenUsingDataSourceAndANegativeTokenValidityThenThrowsWiringException() {
		assertThatCode(() -> this.spring.configLocations(this.xml("NegativeTokenValidityWithDataSource")).autowire())
			.isInstanceOf(FatalBeanException.class);
	}

	@Test
	public void authenticateWithRememberMeWhenTokenValidityIsResolvedByPropertyPlaceholderThenCookieReflectsCorrectExpiration()
			throws Exception {

		this.spring.configLocations(this.xml("Sec2165")).autowire();

		MvcResult result =
				this.mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf()))
						.andExpect(redirectedUrl("/"))
						.andReturn();

		Cookie cookie = rememberMeCookie(result);

		assertThat(cookie.getMaxAge()).isEqualTo(30);
	}

	@Test
	public void authenticateWithRememberMeWhenUseSecureCookieIsTrueThenCookieIsSecure()
			throws Exception {

		this.spring.configLocations(this.xml("SecureCookie")).autowire();

		MvcResult result =
				this.mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf()))
						.andExpect(redirectedUrl("/"))
						.andReturn();

		Cookie cookie = rememberMeCookie(result);

		assertThat(cookie.getSecure()).isEqualTo(true);
	}

	/**
	 * SEC-1827
	 */
	@Test
	public void authenticateWithRememberMeWhenUseSecureCookieIsFalseThenCookieIsNotSecure()
			throws Exception {

		this.spring.configLocations(this.xml("Sec1827")).autowire();

		MvcResult result =
				this.mvc.perform(post("/login")
						.param("username", "user")
						.param("password", "password")
						.param("remember-me", "true")
						.with(csrf()))
						.andExpect(redirectedUrl("/"))
						.andReturn();

		Cookie cookie = rememberMeCookie(result);

		assertThat(cookie.getSecure()).isEqualTo(false);

	}

	@Test
	public void configureWhenUsingPersistentTokenRepositoryAndANegativeTokenValidityThenThrowsWiringException() {
		assertThatCode(() -> this.spring.configLocations(this.xml("NegativeTokenValidityWithPersistentRepository")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class);
	}

	/*
	def 'Custom user service is supported'() {
		when:
		httpAutoConfig () {
			'remember-me'('key': 'ourkey', 'token-validity-seconds':'-1', 'user-service-ref': 'userService')
		}
		bean('userService', MockUserDetailsService.class.name)
		createAppContext(AUTH_PROVIDER_XML)

		then: "Parses OK"
		notThrown BeanDefinitionParsingException
	}

	// SEC-742
	def rememberMeWorksWithoutBasicProcessingFilter() {
		when:
		xml.http () {
			'form-login'('login-page': '/login.jsp', 'default-target-url': '/messageList.html' )
			logout('logout-success-url': '/login.jsp')
			anonymous(username: 'guest', 'granted-authority': 'guest')
			'remember-me'()
		}
		createAppContext(AUTH_PROVIDER_XML)

		then: "Parses OK"
		notThrown BeanDefinitionParsingException
	}

	def 'Default remember-me-parameter is correct'() {
		httpAutoConfig () {
			'remember-me'()
		}

		createAppContext(AUTH_PROVIDER_XML)
		expect:
		rememberMeServices().parameter == AbstractRememberMeServices.DEFAULT_PARAMETER
	}

	// SEC-2119
	def 'Custom remember-me-parameter is supported'() {
		httpAutoConfig () {
			'remember-me'('remember-me-parameter': 'ourParam')
		}

		createAppContext(AUTH_PROVIDER_XML)
		expect:
		rememberMeServices().parameter == 'ourParam'
	}

	def 'remember-me-parameter cannot be used together with services-ref'() {
		when:
		httpAutoConfig () {
			'remember-me'('remember-me-parameter': 'ourParam', 'services-ref': 'ourService')
		}
		createAppContext(AUTH_PROVIDER_XML)
		then:
		BeanDefinitionParsingException e = thrown()
	}

	// SEC-2826
	def 'Custom remember-me-cookie is supported'() {
		httpAutoConfig () {
			'remember-me'('remember-me-cookie': 'ourCookie')
		}

		createAppContext(AUTH_PROVIDER_XML)
		expect:
		rememberMeServices().cookieName == 'ourCookie'
	}

	// SEC-2826
	def 'remember-me-cookie cannot be used together with services-ref'() {
		when:
		httpAutoConfig () {
			'remember-me'('remember-me-cookie': 'ourCookie', 'services-ref': 'ourService')
		}

		createAppContext(AUTH_PROVIDER_XML)
		then:
		BeanDefinitionParsingException e = thrown()
		expect:
		e.message == 'Configuration problem: services-ref can\'t be used in combination with attributes token-repository-ref,data-source-ref, user-service-ref, token-validity-seconds, use-secure-cookie, remember-me-parameter or remember-me-cookie\nOffending resource: null'
	}

	def rememberMeServices() {
		getFilter(RememberMeAuthenticationFilter.class).getRememberMeServices()
	}

	static class CustomTokenRepository extends InMemoryTokenRepositoryImpl {

	}*/

	@RestController
	static class BasicController {
		@GetMapping("/authenticated")
		String ok() {
			return "ok";
		}
	}

	private static Cookie rememberMeCookie(MvcResult result) {
		return result.getResponse().getCookie("remember-me");
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}
}
