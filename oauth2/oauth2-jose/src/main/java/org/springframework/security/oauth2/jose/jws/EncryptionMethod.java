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

package org.springframework.security.oauth2.jose.jws;

public enum EncryptionMethod {

	A256GCM("A256GCM");

	private final String name;

	EncryptionMethod(String name) {
		this.name = name;
	}

	/**
	 * Returns the method name.
	 * @return the method name
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * Attempt to resolve the provided algorithm name to a {@code EncryptionMethod}.
	 * @param name the algorithm name
	 * @return the resolved {@code EncryptionMethod}, or {@code null} if not found
	 */
	public static EncryptionMethod from(String name) {
		for (EncryptionMethod value : values()) {
			if (value.getName().equals(name)) {
				return value;
			}
		}
		return null;
	}
}
