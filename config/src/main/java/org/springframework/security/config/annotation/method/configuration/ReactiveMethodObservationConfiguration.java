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

package org.springframework.security.config.annotation.method.configuration;

import io.micrometer.observation.ObservationRegistry;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.ObservationReactiveAuthorizationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.observation.AbstractObservationObjectPostProcessor;
import org.springframework.security.config.observation.ObservationObjectPostProcessor;

@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
class ReactiveMethodObservationConfiguration {

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static ObjectPostProcessor<ReactiveAuthorizationManager<MethodInvocation>> methodAuthorizationManagerPostProcessor(
			ObjectProvider<ObservationRegistry> registry,
			ObjectProvider<ObservationObjectPostProcessor<ReactiveAuthorizationManager<MethodInvocation>>> postProcessor) {
		return new AbstractMethodSecurityObservationObjectPostProcessor<>(registry, postProcessor) {

		};
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	ObjectPostProcessor<ReactiveAuthorizationManager<MethodInvocationResult>> methodResultAuthorizationManagerPostProcessor(
			ObjectProvider<ObservationRegistry> registry,
			ObjectProvider<ObservationObjectPostProcessor<ReactiveAuthorizationManager<MethodInvocationResult>>> postProcessor) {
		return new AbstractMethodSecurityObservationObjectPostProcessor<>(registry, postProcessor) {

		};
	}

	private static class AbstractMethodSecurityObservationObjectPostProcessor<T>
			extends AbstractObservationObjectPostProcessor<ReactiveAuthorizationManager<T>> {

		ObjectProvider<ObservationObjectPostProcessor<ReactiveAuthorizationManager<T>>> postProcessor;

		AbstractMethodSecurityObservationObjectPostProcessor(ObjectProvider<ObservationRegistry> registry,
				ObjectProvider<ObservationObjectPostProcessor<ReactiveAuthorizationManager<T>>> postProcessor) {
			super(registry);
			this.postProcessor = postProcessor;
		}

		@Override
		protected <O extends ReactiveAuthorizationManager<T>> O postProcess(ObservationRegistry registry, O object) {
			return (O) this.postProcessor.getIfUnique(() -> ObservationReactiveAuthorizationManager::new)
				.postProcess(registry, object);
		}

	}

}
