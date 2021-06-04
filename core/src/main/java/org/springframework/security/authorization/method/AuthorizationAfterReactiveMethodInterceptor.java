/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization.method;

import java.lang.reflect.Method;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.core.CoroutinesUtils;
import org.springframework.core.KotlinDetector;
import org.springframework.core.Ordered;
import org.springframework.core.ReactiveAdapter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.util.Assert;

/**
 * @author Evgeniy Cheban
 */
public final class AuthorizationAfterReactiveMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private final Pointcut pointcut = AuthorizationMethodPointcuts.forAllAnnotations();

	private int order = AuthorizationInterceptorsOrder.LAST.getOrder();

	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		Method method = mi.getMethod();
		Class<?> returnType = method.getReturnType();
		if (Mono.class.isAssignableFrom(returnType)) {
			return Mono.defer(() -> ReactiveMethodInvocationUtils.proceed(mi));
		}
		boolean isSuspendingFunction = KotlinDetector.isSuspendingFunction(method);
		if (ReactiveMethodInvocationUtils.hasFlowReturnType(method)) {
			if (isSuspendingFunction) {
				return Flux
						.defer(() -> CoroutinesUtils.invokeSuspendingFunction(method, mi.getThis(), mi.getArguments()));
			}
			ReactiveAdapter adapter = ReactiveAdapterRegistry.getSharedInstance().getAdapter(returnType);
			Assert.state(adapter != null, () -> "The returnType " + returnType + " on " + mi.getMethod()
					+ " must have a org.springframework.core.ReactiveAdapter registered");
			return Flux.defer(() -> adapter.toPublisher(ReactiveMethodInvocationUtils.proceed(mi)));
		}
		if (isSuspendingFunction) {
			return Mono.defer(
					() -> Mono.from(CoroutinesUtils.invokeSuspendingFunction(method, mi.getThis(), mi.getArguments())));
		}
		return Flux.defer(() -> ReactiveMethodInvocationUtils.proceed(mi));
	}

	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

	@Override
	public Advice getAdvice() {
		return this;
	}

	@Override
	public boolean isPerInstance() {
		return true;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

}
