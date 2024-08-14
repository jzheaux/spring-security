package org.springframework.security.config.annotation.method.configuration;

import java.util.function.Supplier;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import org.springframework.aop.Pointcut;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.util.function.SingletonSupplier;

final class DeferringMethodInterceptor<M extends AuthorizationAdvisor> implements AuthorizationAdvisor {

	private final Pointcut pointcut;

	private final Supplier<M> delegate;

	DeferringMethodInterceptor(Pointcut pointcut, Supplier<M> delegate) {
		this.pointcut = pointcut;
		this.delegate = SingletonSupplier.of(delegate);
	}

	@Nullable
	@Override
	public Object invoke(@NotNull MethodInvocation invocation) throws Throwable {
		return this.delegate.get().invoke(invocation);
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
	public int getOrder() {
		return this.delegate.get().getOrder();
	}

	@Override
	public boolean isPerInstance() {
		return true;
	}

}
