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

package org.springframework.security.aot.hint;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashSet;
import java.util.Set;

import org.springframework.aop.SpringProxy;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.security.authorization.method.AuthorizeReturnObject;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;

public final class AuthorizeReturnObjectHintsRegistrar implements SecurityHintsRegistrar {

	private final AuthorizationProxyFactory proxyFactory;

	private final SecurityAnnotationScanner<AuthorizeReturnObject> scanner = SecurityAnnotationScanners
		.requireUnique(AuthorizeReturnObject.class);

	private final Set<Class<?>> visitedClasses = new HashSet<>();

	private Class<?>[] additionalClasses = new Class<?>[0];

	public AuthorizeReturnObjectHintsRegistrar(AuthorizationProxyFactory proxyFactory) {
		this.proxyFactory = proxyFactory;
	}

	@Override
	public void registerHints(RuntimeHints hints, ConfigurableListableBeanFactory beanFactory) {
		for (String name : beanFactory.getBeanDefinitionNames()) {
			Class<?> clazz = beanFactory.getType(name, false);
			if (clazz == null) {
				continue;
			}
			traverseType(clazz, hints);
		}
		for (Class<?> clazz : this.additionalClasses) {
			traverseType(clazz, hints);
		}
	}

	public void setAdditionalClasses(Class<?>... additionalClasses) {
		this.additionalClasses = additionalClasses;
	}

	private void traverseType(Class<?> clazz, RuntimeHints hints) {
		if (clazz == Object.class || this.visitedClasses.contains(clazz)) {
			return;
		}
		this.visitedClasses.add(clazz);
		for (Method m : clazz.getDeclaredMethods()) {
			AuthorizeReturnObject object = this.scanner.scan(m, clazz);
			if (object == null) {
				continue;
			}
			Class<?> returnType = m.getReturnType();
			registerProxy(hints, returnType);
			traverseType(returnType, hints);
		}
	}

	private void registerProxy(RuntimeHints hints, Class<?> clazz) {
		Class<?> proxied = (Class<?>) this.proxyFactory.proxy(clazz);
		if (Proxy.isProxyClass(proxied)) {
			hints.proxies().registerJdkProxy(proxied.getInterfaces());
			return;
		}
		if (!SpringProxy.class.isAssignableFrom(proxied)) {
			return;
		}
		hints.reflection()
			.registerType(proxied, MemberCategory.INVOKE_PUBLIC_METHODS, MemberCategory.PUBLIC_FIELDS,
					MemberCategory.DECLARED_FIELDS);
	}

}
