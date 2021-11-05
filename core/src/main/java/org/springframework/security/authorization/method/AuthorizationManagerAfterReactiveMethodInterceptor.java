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

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.core.Ordered;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} which can determine if an {@link Authentication} has access
 * to the returned object from the {@link MethodInvocation} using the configured
 * {@link ReactiveAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public final class AuthorizationManagerAfterReactiveMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private final Pointcut pointcut;

	private final ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager;

	private int order = AuthorizationInterceptorsOrder.POST_AUTHORIZE.getOrder();

	/**
	 * Creates an instance for the {@link PostAuthorize} annotation.
	 * @return the {@link AuthorizationManagerAfterReactiveMethodInterceptor} to use
	 */
	public static AuthorizationManagerAfterReactiveMethodInterceptor postAuthorize() {
		return postAuthorize(new PostAuthorizeReactiveAuthorizationManager());
	}

	/**
	 * Creates an instance for the {@link PostAuthorize} annotation.
	 * @param authorizationManager the {@link ReactiveAuthorizationManager} to use
	 * @return the {@link AuthorizationManagerAfterReactiveMethodInterceptor} to use
	 */
	public static AuthorizationManagerAfterReactiveMethodInterceptor postAuthorize(
			ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager) {
		AuthorizationManagerAfterReactiveMethodInterceptor interceptor = new AuthorizationManagerAfterReactiveMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PostAuthorize.class), authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.POST_AUTHORIZE.getOrder());
		return interceptor;
	}

	/**
	 * Creates an instance.
	 * @param pointcut the {@link Pointcut} to use
	 * @param authorizationManager the {@link ReactiveAuthorizationManager} to use
	 */
	public AuthorizationManagerAfterReactiveMethodInterceptor(Pointcut pointcut,
			ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager) {
		Assert.notNull(pointcut, "pointcut cannot be null");
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.pointcut = pointcut;
		this.authorizationManager = authorizationManager;
	}

	/**
	 * Determines if an {@link Authentication} has access to the returned object from the
	 * {@link MethodInvocation} using the configured {@link ReactiveAuthorizationManager}.
	 * @param mi the {@link MethodInvocation} to use
	 * @return the {@link Publisher} from the {@link MethodInvocation} or a
	 * {@link Publisher} error if access is denied
	 */
	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		Object returnedObject = mi.proceed();
		if (returnedObject instanceof Publisher<?>) {
			Mono<Authentication> authentication = ReactiveAuthenticationUtils.getAuthentication();
			if (returnedObject instanceof Mono<?>) {
				return ((Mono<?>) returnedObject).flatMap((result) -> postAuthorize(authentication, mi, result));
			}
			return Flux.from((Publisher<?>) returnedObject)
					.flatMap((result) -> postAuthorize(authentication, mi, result));
		}
		return returnedObject;
	}

	private Mono<?> postAuthorize(Mono<Authentication> authentication, MethodInvocation mi, Object result) {
		return this.authorizationManager.verify(authentication, new MethodInvocationResult(mi, result))
				.thenReturn(result);
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
