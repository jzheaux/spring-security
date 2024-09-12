package org.springframework.security.authorization.method;

import java.lang.reflect.Method;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.support.StaticMethodMatcherPointcut;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.core.annotation.SecurityAnnotationScanners;

public final class AuthorizationProxyTargetMethodInterceptor implements AuthorizationAdvisor {

	private static final Pointcut PROXY_TARGET_POINTCUT = new StaticMethodMatcherPointcut() {
		private final SecurityAnnotationScanner<AuthorizeReturnObject> scanner = SecurityAnnotationScanners
			.requireUnique(AuthorizeReturnObject.class);

		@Override
		public boolean matches(Method method, Class<?> targetClass) {
			if (method.getParameters().length == 0) {
				return false;
			}
			for (Method declared : targetClass.getDeclaredMethods()) {
				if (this.scanner.scan(declared, targetClass) != null) {
					return true;
				}
			}
			return false;
		}
	};

	private final AuthorizationProxyTargetFactory targetFactory;

	public AuthorizationProxyTargetMethodInterceptor(AuthorizationProxyTargetFactory targetFactory) {
		this.targetFactory = targetFactory;
	}

	@Override
	public Object invoke(MethodInvocation invocation) throws Throwable {
		Object[] args = invocation.getArguments();
		for (int i = 0; i < args.length; i++) {
			args[i] = this.targetFactory.target(args[i]);
		}
		return invocation.proceed();
	}

	@Override
	public Pointcut getPointcut() {
		return PROXY_TARGET_POINTCUT;
	}

	@Override
	public Advice getAdvice() {
		return this;
	}

	@Override
	public int getOrder() {
		return AuthorizationInterceptorsOrder.PROXY_TARGET.getOrder();
	}

}
