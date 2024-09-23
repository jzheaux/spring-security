/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.observation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link SecurityObservabilityDefaults}
 */
public class SecurityObservationPredicateTests {

	@Test
	void withDefaultsThenFilterOffAuthenticationOnAuthorizationOn() {
		SecurityObservationPredicate defaults = SecurityObservationPredicate.withDefaults().build();
		assertThat(defaults.test("spring.security.filterchains", null)).isFalse();
		assertThat(defaults.test("spring.security.http.secured.requests", null)).isFalse();
		assertThat(defaults.test("spring.security.authentications", null)).isTrue();
		assertThat(defaults.test("spring.security.authorizations", null)).isTrue();
	}

	@Test
	void noObservationsWhenConstructedThenAllOff() {
		SecurityObservationPredicate defaults = SecurityObservationPredicate.noObservations();
		assertThat(defaults.test("spring.security.filterchains", null)).isFalse();
		assertThat(defaults.test("spring.security.http.secured.requests", null)).isFalse();
		assertThat(defaults.test("spring.security.authentications", null)).isFalse();
		assertThat(defaults.test("spring.security.authorizations", null)).isFalse();
	}

	@Test
	void withDefaultsWhenExclusionsThenInstanceReflects() {
		SecurityObservationPredicate defaults = SecurityObservationPredicate.withDefaults()
			.shouldObserveAuthentications(false)
			.shouldObserveAuthorizations(false)
			.shouldObserveRequests(true)
			.build();
		assertThat(defaults.test("spring.security.filterchains", null)).isTrue();
		assertThat(defaults.test("spring.security.http.secured.requests", null)).isTrue();
		assertThat(defaults.test("spring.security.authentications", null)).isFalse();
		assertThat(defaults.test("spring.security.authorizations", null)).isFalse();
	}

}
