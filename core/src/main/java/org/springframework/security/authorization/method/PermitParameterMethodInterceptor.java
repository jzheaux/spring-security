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

package org.springframework.security.authorization.method;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.support.StaticMethodMatcherPointcut;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;

public final class PermitParameterMethodInterceptor implements AuthorizationAdvisor {

	private final SecurityAnnotationScanner<PermitParameter> scanner = SecurityAnnotationScanners
		.requireUnique(PermitParameter.class);

	private Pointcut pointcut = new StaticMethodMatcherPointcut() {
		@Override
		public boolean matches(Method method, Class<?> targetClass) {
			return PermitParameterMethodInterceptor.this.scanner.scan(method, targetClass) != null
					|| anyParameters(method);
		}

		private boolean anyParameters(Method method) {
			for (Parameter parameter : method.getParameters()) {
				if (PermitParameterMethodInterceptor.this.scanner.scan(parameter) != null) {
					return true;
				}
			}
			return false;
		}
	};

	private int order = AuthorizationInterceptorsOrder.PERMIT_PARAMETER.getOrder();

	@Override
	public Object invoke(MethodInvocation invocation) throws Throwable {
		Object[] args = invocation.getArguments();
		boolean entireMethod = this.scanner.scan(invocation.getMethod(), invocation.getThis().getClass()) != null;
		for (int i = 0; i < args.length; i++) {
			if (!entireMethod && this.scanner.scan(invocation.getMethod().getParameters()[i]) == null) {
				continue;
			}
			if (args[i] instanceof AuthorizationProxy authorized) {
				args[i] = authorized.toAuthorizedTarget();
			}
		}
		return invocation.proceed();
	}

	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

	public void setPointcut(Pointcut pointcut) {
		this.pointcut = pointcut;
	}

	@Override
	public Advice getAdvice() {
		return this;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

}
