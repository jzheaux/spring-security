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
import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.prepost.PostFilter;

/**
 * A {@link MethodInterceptor} which filters the returned object from the
 * {@link MethodInvocation} by evaluating an expression from the {@link PostFilter}
 * annotation.
 *
 * @author Evgeniy Cheban
 */
public final class PostFilterAuthorizationReactiveMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private final PostFilterExpressionAttributeRegistry registry = new PostFilterExpressionAttributeRegistry();

	private final Pointcut pointcut;

	private int order = AuthorizationInterceptorsOrder.POST_FILTER.getOrder();

	/**
	 * Creates an instance.
	 */
	public PostFilterAuthorizationReactiveMethodInterceptor() {
		this.pointcut = AuthorizationMethodPointcuts.forAnnotations(PostFilter.class);
	}

	/**
	 * Sets the {@link MethodSecurityExpressionHandler}.
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		this.registry.setExpressionHandler(expressionHandler);
	}

	/**
	 * Filters the returned object from the {@link MethodInvocation} by evaluating an
	 * expression from the {@link PostFilter} annotation.
	 * @param mi the {@link MethodInvocation} to use
	 * @return the {@link Publisher} to use
	 */
	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		Object returnedObject = mi.proceed();
		ExpressionAttribute attribute = this.registry.getAttribute(mi);
		if (attribute == ExpressionAttribute.NULL_ATTRIBUTE) {
			return returnedObject;
		}
		if (returnedObject instanceof Publisher<?>) {
			Mono<EvaluationContext> toInvoke = ReactiveAuthenticationUtils.getAuthentication()
					.map((auth) -> this.registry.getExpressionHandler().createEvaluationContext(auth, mi));
			if (returnedObject instanceof Mono<?>) {
				return toInvoke.flatMap((ctx) -> filterMono((Mono<?>) returnedObject, ctx, attribute));
			}
			return toInvoke.flatMapMany((ctx) -> filterPublisher((Publisher<?>) returnedObject, ctx, attribute));
		}
		return returnedObject;
	}

	private Mono<?> filterMono(Mono<?> mono, EvaluationContext ctx, ExpressionAttribute attribute) {
		return mono.doOnNext((result) -> setFilterObject(ctx, result))
				.flatMap((result) -> postFilter(ctx, result, attribute));
	}

	private Flux<?> filterPublisher(Publisher<?> publisher, EvaluationContext ctx, ExpressionAttribute attribute) {
		return Flux.from(publisher).doOnNext((result) -> setFilterObject(ctx, result))
				.flatMap((result) -> postFilter(ctx, result, attribute));
	}

	private void setFilterObject(EvaluationContext ctx, Object result) {
		((MethodSecurityExpressionOperations) ctx.getRootObject().getValue()).setFilterObject(result);
	}

	private Mono<?> postFilter(EvaluationContext ctx, Object result, ExpressionAttribute attribute) {
		return ReactiveExpressionUtils.evaluateAsBoolean(attribute.getExpression(), ctx)
				.flatMap((granted) -> granted ? Mono.just(result) : Mono.empty());
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
