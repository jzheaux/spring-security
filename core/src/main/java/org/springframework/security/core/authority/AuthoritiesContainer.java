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

package org.springframework.security.core.authority;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import org.springframework.security.core.GrantedAuthority;

public interface AuthoritiesContainer {

	Collection<? extends GrantedAuthority> getAuthorities();

	default Collection<GrantedAuthority> getGrantedAuthorities() {
		Set<GrantedAuthority> granted = new HashSet<>();
		for (GrantedAuthority authority : getAuthorities()) {
			if (authority.isGranted()) {
				granted.add(authority);
			}
		}
		return granted;
	}

	AuthoritiesContainer grantAuthorities(Consumer<Collection<GrantedAuthority>> authorities);

}
