package org.springframework.security.authorization.method;

public interface AuthorizationProxyTargetFactory {

	Object target(Object object);

}
