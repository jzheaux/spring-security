/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.core;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

/**
 * for internal use only
 */
public final class OpenSamlObjectUtils {

	private static final boolean isAtLeastVersion5 = ClassUtils
		.isPresent("net.shibboleth.shared.xml.impl.BasicParserPool", null);

	public static <T> T cast(Object source) {
		return (T) source;
	}

	public static <T> T invokeConstructor(String simpleClassName, Object... args) {
		Class<?> clazz = forSimpleName(simpleClassName);
		try {
			for (Constructor<?> cons : clazz.getConstructors()) {
				if (allAreAssignableFrom(cons.getParameterTypes(), args)) {
					return (T) invoker(cons).invoke(null, args);
				}
			}
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
		return null;
	}

	public static <T> T invokeMethod(Object target, String methodName, Object... args) {
		Class<?> clazz = target.getClass();
		for (Method method : clazz.getMethods()) {
			if (!method.getName().equals(methodName)) {
				continue;
			}
			if (allAreAssignableFrom(method.getParameterTypes(), args)) {
				return (T) invoker(method).invoke(target, args);
			}
		}
		return null;
	}

	public static <T> T invokeStaticMethod(String simpleClassName, String methodName, Object... args) {
		Class<?> clazz = forSimpleName(simpleClassName);
		for (Method method : clazz.getMethods()) {
			if (!method.getName().equals(methodName)) {
				continue;
			}
			if (allAreAssignableFrom(method.getParameterTypes(), args)) {
				return (T) invoker(method).invoke(null, args);
			}
		}
		return null;
	}

	public static String toString(Object object) {
		StringBuilder sb = new StringBuilder();
		for (Field field : object.getClass().getDeclaredFields()) {
			ReflectionUtils.makeAccessible(field);
			Object value = ReflectionUtils.getField(field, object);
			sb.append(field.getName() + " = " + value + ",");
		}
		sb.deleteCharAt(sb.length() - 1);
		return sb.toString();
	}

	private static boolean allAreAssignableFrom(Class<?>[] parameterTypes, Object[] args) {
		if (parameterTypes.length != args.length) {
			return false;
		}
		for (int i = 0; i < parameterTypes.length; i++) {
			if (!parameterTypes[i].isAssignableFrom(args[i].getClass())) {
				return false;
			}
		}
		return true;
	}

	private static Class<?> forSimpleName(String simpleClassName) {
		try {
			return isAtLeastVersion5 ? Class.forName("net.shibboleth.shared." + simpleClassName)
					: Class.forName("net.shibboleth.utilities.java.support." + simpleClassName);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	private static <T> Invoker<T> invoker(Method method) {
		return (target, args) -> {
			try {
				return (T) method.invoke(target, args);
			}
			catch (Exception ex) {
				throw new Saml2Exception(ex);
			}
		};
	}

	private static <T> Invoker<T> invoker(Constructor<?> cons) {
		return (target, args) -> {
			try {
				return (T) cons.newInstance(args);
			}
			catch (Exception ex) {
				throw new Saml2Exception(ex);
			}
		};
	}

	private OpenSamlObjectUtils() {

	}

	interface Invoker<T> {

		T invoke(Object target, Object... args);

	}

}
