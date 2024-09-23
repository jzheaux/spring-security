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

import io.micrometer.observation.ObservationRegistry;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;

/**
 * An {@link ObjectPostProcessor} that conditionally post-processes observable components
 * based on whether {@link ObservationRegistry} is switched on
 *
 * @param <T> the type of observable component
 * @author Josh Cummings
 * @since 6.4
 */
public abstract class AbstractObservationObjectPostProcessor<T> implements ObjectPostProcessor<T> {

	final ObjectProvider<ObservationRegistry> registry;

	protected AbstractObservationObjectPostProcessor(ObjectProvider<ObservationRegistry> registry) {
		this.registry = registry;
	}

	@Override
	public <O extends T> O postProcess(O object) {
		ObservationRegistry registry = this.registry.getIfUnique(() -> ObservationRegistry.NOOP);
		if (registry.isNoop()) {
			return object;
		}
		return postProcess(registry, object);
	}

	/**
	 * Enhance the given object for observations
	 * @param registry the {@link ObservationRegistry} to use
	 * @param object the instance to enhance for observations
	 * @return the observation-enhanced instance
	 */
	protected abstract <O extends T> O postProcess(ObservationRegistry registry, O object);

}
