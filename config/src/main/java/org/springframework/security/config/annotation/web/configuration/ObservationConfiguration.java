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

package org.springframework.security.config.annotation.web.configuration;

import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ObservationAuthenticationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.observation.AbstractObservationObjectPostProcessor;
import org.springframework.security.config.observation.ObservationObjectPostProcessor;
import org.springframework.security.web.FilterChainProxy.FilterChainDecorator;
import org.springframework.security.web.ObservationFilterChainDecorator;

@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
class ObservationConfiguration {

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static ObjectPostProcessor<AuthorizationManager<HttpServletRequest>> webAuthorizationManagerPostProcessor(
			ObjectProvider<ObservationRegistry> registry,
			ObjectProvider<ObservationObjectPostProcessor<AuthorizationManager<HttpServletRequest>>> postProcessor) {
		return new AbstractObservationObjectPostProcessor<>(registry) {
			@Override
			protected <O extends AuthorizationManager<HttpServletRequest>> O postProcess(ObservationRegistry registry,
					O object) {
				return (O) postProcessor.getIfUnique(() -> ObservationAuthorizationManager::new)
					.postProcess(registry, object);
			}
		};
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static ObjectPostProcessor<AuthenticationManager> authenticationManagerPostProcessor(
			ObjectProvider<ObservationRegistry> registry,
			ObjectProvider<ObservationObjectPostProcessor<AuthenticationManager>> postProcessor) {
		return new AbstractObservationObjectPostProcessor<>(registry) {
			@Override
			protected AuthenticationManager postProcess(ObservationRegistry registry, AuthenticationManager object) {
				return postProcessor.getIfUnique(() -> ObservationAuthenticationManager::new)
					.postProcess(registry, object);
			}
		};
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static ObjectPostProcessor<FilterChainDecorator> filterChainDecoratorPostProcessor(
			ObjectProvider<ObservationRegistry> registry,
			ObjectProvider<ObservationObjectPostProcessor<FilterChainDecorator>> postProcessor) {
		return new AbstractObservationObjectPostProcessor<>(registry) {
			@Override
			protected FilterChainDecorator postProcess(ObservationRegistry registry, FilterChainDecorator object) {
				return postProcessor.getIfUnique(() -> (r, o) -> new ObservationFilterChainDecorator(r))
					.postProcess(registry, object);
			}
		};
	}

}
