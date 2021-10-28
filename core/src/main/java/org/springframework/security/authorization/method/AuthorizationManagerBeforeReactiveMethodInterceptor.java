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
import java.util.Collection;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.reactivestreams.Publisher;
import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.core.CoroutinesUtils;
import org.springframework.core.KotlinDetector;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.ReactiveAdapter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PrePostAdviceReactiveMethodInterceptor;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} which can determine if an {@link Authentication} has access
 * to the {@link MethodInvocation} using the configured
 * {@link ReactiveAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public final class AuthorizationManagerBeforeReactiveMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private final Pointcut pointcut;

	private final ReactiveAuthorizationManager<MethodInvocation> authorizationManager;

	private int order;

	/**
	 * Creates an instance for the {@link PreAuthorize} annotation.
	 * @return the {@link AuthorizationManagerBeforeReactiveMethodInterceptor} to use
	 */
	public static AuthorizationManagerBeforeReactiveMethodInterceptor preAuthorize() {
		return preAuthorize(new PreAuthorizeReactiveAuthorizationManager());
	}

	/**
	 * Creates an instance for the {@link PreAuthorize} annotation.
	 * @param authorizationManager the {@link ReactiveAuthorizationManager} to use
	 * @return the {@link AuthorizationManagerBeforeReactiveMethodInterceptor} to use
	 */
	public static AuthorizationManagerBeforeReactiveMethodInterceptor preAuthorize(
			ReactiveAuthorizationManager<MethodInvocation> authorizationManager) {
		AuthorizationManagerBeforeReactiveMethodInterceptor interceptor = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class), authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder());
		return interceptor;
	}

	/**
	 * Creates an instance.
	 * @param pointcut the {@link Pointcut} to use
	 * @param authorizationManager the {@link ReactiveAuthorizationManager} to use
	 */
	public AuthorizationManagerBeforeReactiveMethodInterceptor(Pointcut pointcut,
			ReactiveAuthorizationManager<MethodInvocation> authorizationManager) {
		Assert.notNull(pointcut, "pointcut cannot be null");
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.pointcut = pointcut;
		this.authorizationManager = authorizationManager;
	}

	/**
	 * Determines if an {@link Authentication} has access to the {@link MethodInvocation}
	 * using the configured {@link ReactiveAuthorizationManager}.
	 * @param invocation the {@link MethodInvocation} to use
	 * @return the {@link Publisher} from the {@link MethodInvocation} or a
	 * {@link Publisher} error if access is denied
	 */
	@Override
	public Object invoke(MethodInvocation invocation) throws Throwable {
		Method method = invocation.getMethod();
		Class<?> returnType = method.getReturnType();

		boolean isSuspendingFunction = KotlinDetector.isSuspendingFunction(method);
		boolean hasFlowReturnType = COROUTINES_FLOW_CLASS_NAME
				.equals(new MethodParameter(method, RETURN_TYPE_METHOD_PARAMETER_INDEX).getParameterType().getName());
		boolean hasReactiveReturnType = Publisher.class.isAssignableFrom(returnType) || isSuspendingFunction
				|| hasFlowReturnType;

		Assert.state(hasReactiveReturnType,
				() -> "The returnType " + returnType + " on " + method
						+ " must return an instance of org.reactivestreams.Publisher "
						+ "(i.e. Mono / Flux) or the function must be a Kotlin coroutine "
						+ "function in order to support Reactor Context");
		Class<?> targetClass = invocation.getThis().getClass();
		// @formatter:off
		Mono<Authentication> toInvoke = ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.defaultIfEmpty(this.anonymous)
				.filter((auth) -> this.preInvocationAdvice.before(auth, invocation, preAttr))
				.switchIfEmpty(Mono.defer(() -> Mono.error(new AccessDeniedException("Denied"))));
		// @formatter:on
		PostInvocationAttribute attr = findPostInvocationAttribute(attributes);
		if (Mono.class.isAssignableFrom(returnType)) {
			return toInvoke.flatMap((auth) -> ReactiveMethodInvocationUtils.proceed(invocation).<Mono<?>>proceed(invocation)
					.map((r) -> (attr != null) ? this.postAdvice.after(auth, invocation, attr, r) : r));
		}
		if (Flux.class.isAssignableFrom(returnType)) {
			return toInvoke.flatMapMany((auth) -> PrePostAdviceReactiveMethodInterceptor.<Flux<?>>proceed(invocation)
					.map((r) -> (attr != null) ? this.postAdvice.after(auth, invocation, attr, r) : r));
		}
		if (hasFlowReturnType) {
			Flux<?> response;
			if (isSuspendingFunction) {
				response = toInvoke.flatMapMany((auth) -> Flux
						.from(CoroutinesUtils.invokeSuspendingFunction(invocation.getMethod(), invocation.getThis(),
								invocation.getArguments()))
						.map((r) -> (attr != null) ? this.postAdvice.after(auth, invocation, attr, r) : r));
			}
			else {
				ReactiveAdapter adapter = ReactiveAdapterRegistry.getSharedInstance().getAdapter(returnType);
				Assert.state(adapter != null, () -> "The returnType " + returnType + " on " + method
						+ " must have a org.springframework.core.ReactiveAdapter registered");
				response = toInvoke.flatMapMany((auth) -> Flux
						.from(adapter.toPublisher(PrePostAdviceReactiveMethodInterceptor.flowProceed(invocation)))
						.map((r) -> (attr != null) ? this.postAdvice.after(auth, invocation, attr, r) : r));
			}
			return KotlinDelegate.asFlow(response);
		}
		if (isSuspendingFunction) {
			Mono<?> response = toInvoke.flatMap((auth) -> Mono
					.from(CoroutinesUtils.invokeSuspendingFunction(invocation.getMethod(), invocation.getThis(),
							invocation.getArguments()))
					.map((r) -> (attr != null) ? this.postAdvice.after(auth, invocation, attr, r) : r));
			return KotlinDelegate.awaitSingleOrNull(response,
					invocation.getArguments()[invocation.getArguments().length - 1]);
		}
		return toInvoke.flatMapMany(
				(auth) -> Flux.from(PrePostAdviceReactiveMethodInterceptor.<Publisher<?>>proceed(invocation))
						.map((r) -> (attr != null) ? this.postAdvice.after(auth, invocation, attr, r) : r));
	}

	private static <T extends Publisher<?>> T proceed(final MethodInvocation invocation) {
		try {
			return (T) invocation.proceed();
		}
		catch (Throwable throwable) {
			throw Exceptions.propagate(throwable);
		}
	}

	private static Object flowProceed(final MethodInvocation invocation) {
		try {
			return invocation.proceed();
		}
		catch (Throwable throwable) {
			throw Exceptions.propagate(throwable);
		}
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
