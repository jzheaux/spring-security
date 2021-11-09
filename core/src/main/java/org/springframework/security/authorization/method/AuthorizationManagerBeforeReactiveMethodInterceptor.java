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

import kotlin.coroutines.Continuation;
import kotlinx.coroutines.reactive.AwaitKt;
import kotlinx.coroutines.reactive.ReactiveFlowKt;
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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
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

	private Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymous",
			AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private final Pointcut pointcut;

	private final ReactiveAuthorizationManager<MethodInvocation> authorizationManager;

	private int order;

	private static final String COROUTINES_FLOW_CLASS_NAME = "kotlinx.coroutines.flow.Flow";

	private static final int RETURN_TYPE_METHOD_PARAMETER_INDEX = -1;

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
		// @formatter:off
		Mono<Authentication> authentication = ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.switchIfEmpty(Mono.just(this.anonymous));
		Mono<Void> toInvoke = this.authorizationManager.verify(authentication, invocation);
		// @formatter:on
		if (Mono.class.isAssignableFrom(returnType)) {
			return toInvoke.then(Mono.defer(() -> ReactiveMethodInvocationUtils.proceed(invocation)));
		}
		if (Flux.class.isAssignableFrom(returnType)) {
			return toInvoke.thenMany(Flux.defer(() -> ReactiveMethodInvocationUtils.proceed(invocation)));
		}
		if (hasFlowReturnType) {
			Flux<?> response;
			if (isSuspendingFunction) {
				response = toInvoke.thenMany(
						Flux.defer(() -> Flux.from(CoroutinesUtils.invokeSuspendingFunction(invocation.getMethod(),
								invocation.getThis(), invocation.getArguments()))));
			}
			else {
				ReactiveAdapter adapter = ReactiveAdapterRegistry.getSharedInstance().getAdapter(returnType);
				Assert.state(adapter != null, () -> "The returnType " + returnType + " on " + method
						+ " must have a org.springframework.core.ReactiveAdapter registered");
				response = toInvoke.thenMany(Flux.defer(() -> Flux.from(adapter.toPublisher(flowProceed(invocation)))));
			}
			return KotlinDelegate.asFlow(response);
		}
		if (isSuspendingFunction) {
			Mono<?> response = toInvoke
					.then(Mono.defer(() -> Mono.from(CoroutinesUtils.invokeSuspendingFunction(invocation.getMethod(),
							invocation.getThis(), invocation.getArguments()))));
			return KotlinDelegate.awaitSingleOrNull(response,
					invocation.getArguments()[invocation.getArguments().length - 1]);
		}
		return toInvoke.thenMany(Flux.defer(() -> Flux.from(ReactiveMethodInvocationUtils.proceed(invocation))));
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

	/**
	 * Inner class to avoid a hard dependency on Kotlin at runtime.
	 */
	private static class KotlinDelegate {

		private static Object asFlow(Publisher<?> publisher) {
			return ReactiveFlowKt.asFlow(publisher);
		}

		private static Object awaitSingleOrNull(Publisher<?> publisher, Object continuation) {
			return AwaitKt.awaitSingleOrNull(publisher, (Continuation<Object>) continuation);
		}

	}

}
