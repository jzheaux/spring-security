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

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationPredicate;

public final class SecurityObservationPredicate implements ObservationPredicate {

	private boolean observeRequests;

	private boolean observeAuthentications;

	private boolean observeAuthorizations;

	private SecurityObservationPredicate(boolean observeRequests, boolean observeAuthentications,
			boolean observeAuthorizations) {
		this.observeRequests = observeRequests;
		this.observeAuthentications = observeAuthentications;
		this.observeAuthorizations = observeAuthorizations;
	}

	/**
	 * Make no Spring Security observations
	 * @return a {@link SecurityObservationPredicate} with all exclusions turned on
	 */
	public static SecurityObservationPredicate noObservations() {
		return new SecurityObservationPredicate(false, false, false);
	}

	/**
	 * Begin the configuration of a {@link SecurityObservationPredicate}
	 * @return a {@link Builder} where filter chain observations are off and authn/authz
	 * observations are on
	 */
	public static Builder withDefaults() {
		return new Builder(false, true, true);
	}

	@Override
	public boolean test(String name, Observation.Context context) {
		boolean passes = true;
		if (!this.observeRequests) {
			passes = passes && !"spring.security.filterchains".equals(name) && !name.startsWith("spring.security.http");
		}
		if (!this.observeAuthentications) {
			passes = passes && !"spring.security.authentications".equals(name);
		}
		if (!this.observeAuthorizations) {
			passes = passes && !"spring.security.authorizations".equals(name);
		}
		return passes;
	}

	/**
	 * A builder for configuring a {@link SecurityObservationPredicate}
	 */
	public static final class Builder {

		private boolean observeRequests;

		private boolean observeAuthentications;

		private boolean observeAuthorizations;

		Builder(boolean observeRequests, boolean observeAuthentications, boolean observeAuthorizations) {
			this.observeRequests = observeRequests;
			this.observeAuthentications = observeAuthentications;
			this.observeAuthorizations = observeAuthorizations;
		}

		public Builder shouldObserveRequests(boolean excludeFilters) {
			this.observeRequests = excludeFilters;
			return this;
		}

		public Builder shouldObserveAuthentications(boolean excludeAuthentications) {
			this.observeAuthentications = excludeAuthentications;
			return this;
		}

		public Builder shouldObserveAuthorizations(boolean excludeAuthorizations) {
			this.observeAuthorizations = excludeAuthorizations;
			return this;
		}

		public SecurityObservationPredicate build() {
			return new SecurityObservationPredicate(this.observeRequests, this.observeAuthentications,
					this.observeAuthorizations);
		}

	}

}
