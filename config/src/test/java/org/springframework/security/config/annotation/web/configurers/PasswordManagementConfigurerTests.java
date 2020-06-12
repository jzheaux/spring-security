/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link PasswordManagementConfigurer}.
 *
 * @author Evgeniy Cheban
 */
public class PasswordManagementConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void whenChangePasswordPageNotSetThenDefaultChangePasswordPageUsed() throws Exception {
		this.spring.register(PasswordManagementWithDefaultChangePasswordPageConfig.class).autowire();

		this.mvc.perform(get("/.well-known/change-password"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/change-password"));
	}

	@EnableWebSecurity
	static class PasswordManagementWithDefaultChangePasswordPageConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.passwordManagement(withDefaults());
		}
	}

	@Test
	public void whenChangePasswordPageSetThenSpecifiedChangePasswordPageUsed() throws Exception {
		this.spring.register(PasswordManagementWithCustomChangePasswordPageConfig.class).autowire();

		this.mvc.perform(get("/.well-known/change-password"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/custom-change-password-page"));
	}

	@EnableWebSecurity
	static class PasswordManagementWithCustomChangePasswordPageConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.passwordManagement(passwordManagement ->
					passwordManagement.changePasswordPage("/custom-change-password-page")
			);
		}
	}

	@Test
	public void whenSettingNullChangePasswordPage() {
		PasswordManagementConfigurer configurer = new PasswordManagementConfigurer();
		assertThatIllegalArgumentException()
				.isThrownBy(() -> configurer.changePasswordPage(null))
				.withMessage("changePasswordPage cannot be empty");
	}

	@Test
	public void whenSettingEmptyChangePasswordPage() {
		PasswordManagementConfigurer configurer = new PasswordManagementConfigurer();
		assertThatIllegalArgumentException()
				.isThrownBy(() -> configurer.changePasswordPage(""))
				.withMessage("changePasswordPage cannot be empty");
	}

	@Test
	public void whenSettingBlankChangePasswordPage() {
		PasswordManagementConfigurer configurer = new PasswordManagementConfigurer();
		assertThatIllegalArgumentException()
				.isThrownBy(() -> configurer.changePasswordPage(" "))
				.withMessage("changePasswordPage cannot be empty");
	}
}
