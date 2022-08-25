/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

public final class UserDetailsServiceAuthenticationManager implements AuthenticationManager, MessageSourceAware {
	private final Log logger = LogFactory.getLog(getClass());

	private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";

	/**
	 * The password used to perform {@link PasswordEncoder#matches(CharSequence, String)}
	 * on when the user is not found to avoid SEC-2056. This is necessary, because some
	 * {@link PasswordEncoder} implementations will short circuit if the password is not
	 * in a valid format.
	 */
	private volatile String userNotFoundEncodedPassword;

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

	private UserDetailsService userDetailsService;

	private UserDetailsPasswordService userDetailsPasswordService;

	private Converter<UserDetails, Authentication> userDetailsAuthenticationConverter = this::createUsernamePasswordAuthenticationToken;

	private UserDetailsChecker preAuthenticationChecks = this::defaultPreAuthenticationChecks;

	private UserDetailsChecker postAuthenticationChecks = this::defaultPostAuthenticationChecks;

	public UserDetailsServiceAuthenticationManager(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	private void defaultPreAuthenticationChecks(UserDetails user) {
		if (!user.isAccountNonLocked()) {
			this.logger.debug("User account is locked");
			throw new LockedException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.locked",
					"User account is locked"));
		}
		if (!user.isEnabled()) {
			this.logger.debug("User account is disabled");
			throw new DisabledException(
					this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.disabled", "User is disabled"));
		}
		if (!user.isAccountNonExpired()) {
			this.logger.debug("User account is expired");
			throw new AccountExpiredException(this.messages
					.getMessage("AbstractUserDetailsAuthenticationProvider.expired", "User account has expired"));
		}
	}

	private void defaultPostAuthenticationChecks(UserDetails user) {
		if (!user.isCredentialsNonExpired()) {
			this.logger.debug("User account credentials have expired");
			throw new CredentialsExpiredException(this.messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.credentialsExpired", "User credentials have expired"));
		}
	}

	@Override
	public Authentication authenticate(Authentication authentication) {
		String presentedPassword = (String) authentication.getCredentials();
		// @formatter:off
		UserDetails user = retrieveUser(authentication);
		this.preAuthenticationChecks.check(user);
		if (!this.passwordEncoder.matches(presentedPassword, user.getPassword())) {
			throw new BadCredentialsException("Invalid Credentials");
		}
		user = upgradeEncodingIfNecessary(user, presentedPassword);
		this.postAuthenticationChecks.check(user);
		return this.userDetailsAuthenticationConverter.convert(user);
	}

	private UserDetails upgradeEncodingIfNecessary(UserDetails userDetails, String presentedPassword) {
		boolean upgradeEncoding = this.userDetailsPasswordService != null
				&& this.passwordEncoder.upgradeEncoding(userDetails.getPassword());
		if (upgradeEncoding) {
			String newPassword = this.passwordEncoder.encode(presentedPassword);
			return this.userDetailsPasswordService.updatePassword(userDetails, newPassword);
		}
		return userDetails;
	}

	private UsernamePasswordAuthenticationToken createUsernamePasswordAuthenticationToken(UserDetails userDetails) {
		return UsernamePasswordAuthenticationToken.authenticated(userDetails, userDetails.getPassword(),
				userDetails.getAuthorities());
	}

	/**
	 * The {@link PasswordEncoder} that is used for validating the password. The default
	 * is {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}
	 * @param passwordEncoder the {@link PasswordEncoder} to use. Cannot be null
	 */
	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * Sets the service to use for upgrading passwords on successful authentication.
	 * @param userDetailsPasswordService the service to use
	 */
	public void setUserDetailsPasswordService(UserDetailsPasswordService userDetailsPasswordService) {
		this.userDetailsPasswordService = userDetailsPasswordService;
	}

	/**
	 * Sets the strategy which will be used to validate the loaded <tt>UserDetails</tt>
	 * object after authentication occurs.
	 * @param postAuthenticationChecks The {@link UserDetailsChecker}
	 */
	public void setPostAuthenticationChecks(UserDetailsChecker postAuthenticationChecks) {
		Assert.notNull(this.postAuthenticationChecks, "postAuthenticationChecks cannot be null");
		this.postAuthenticationChecks = postAuthenticationChecks;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

	private UserDetails retrieveUser(Authentication authentication) {
		prepareTimingAttackProtection();
		try {
			return this.userDetailsService.loadUserByUsername(authentication.getName());
		} catch (UsernameNotFoundException ex) {
			mitigateAgainstTimingAttack(authentication);
			throw ex;
		}
	}

	private void prepareTimingAttackProtection() {
		if (this.userNotFoundEncodedPassword == null) {
			this.userNotFoundEncodedPassword = this.passwordEncoder.encode(USER_NOT_FOUND_PASSWORD);
		}
	}

	private void mitigateAgainstTimingAttack(Authentication authentication) {
		if (authentication.getCredentials() != null) {
			String presentedPassword = authentication.getCredentials().toString();
			this.passwordEncoder.matches(presentedPassword, this.userNotFoundEncodedPassword);
		}
	}
}
