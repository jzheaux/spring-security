/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.authorization;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthoritiesContainer;

public interface AuthoritiesGranter {

	AuthoritiesContainer grantAuthorities(AuthoritiesContainer authentication);

	default Boolean grantsAuthority(GrantedAuthority authority) {
		return null;
	}

	default Collection<GrantedAuthority> neededAuthorities(AuthoritiesContainer authentication) {
		Set<GrantedAuthority> valid = new HashSet<>(authentication.getGrantedAuthorities());
		Set<GrantedAuthority> granted = new HashSet<>(grantAuthorities(authentication).getGrantedAuthorities());
		Set<GrantedAuthority> needed = new HashSet<>();
		for (GrantedAuthority grant : granted) {
			if (valid.contains(grant)) {
				needed.add(grant);
			}
		}
		return needed;
	}

}
