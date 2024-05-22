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

package org.springframework.security.saml2.provider.service.registration;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.Callable;

import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.Assert;

public final class CachingRelyingPartyRegistrationRepository
		implements RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {

	private final ResourceLoader resourceLoader = new DefaultResourceLoader();

	private final Callable<Map<String, RelyingPartyRegistration>> registrationLoader;

	private Cache cache = new ConcurrentMapCache("registrations");

	private Converter<RelyingPartyRegistration.Builder, RelyingPartyRegistration> relyingPartyRegistrationBuilder = RelyingPartyRegistration.Builder::build;

	public CachingRelyingPartyRegistrationRepository(String metadataLocation,
			RelyingPartyRegistrationsDecoder decoder) {
		this.registrationLoader = () -> {
			Map<String, RelyingPartyRegistration> registrations = new HashMap<>();
			try (InputStream source = this.resourceLoader.getResource(metadataLocation).getInputStream()) {
				for (RelyingPartyRegistration registration : decoder.decode(source)) {
					registrations.put(registration.getRegistrationId(), registration);
				}
				return registrations;
			}
		};
	}

	@Override
	public Iterator<RelyingPartyRegistration> iterator() {
		return registrations().values().iterator();
	}

	@Override
	public RelyingPartyRegistration findByRegistrationId(String registrationId) {
		return registrations().get(registrationId);
	}

	private Map<String, RelyingPartyRegistration> registrations() {
		return this.cache.get("registrations", this.registrationLoader);
	}

	public void setCache(Cache cache) {
		Assert.notNull(cache, "cache cannot be null");
		this.cache = cache;
	}

}
