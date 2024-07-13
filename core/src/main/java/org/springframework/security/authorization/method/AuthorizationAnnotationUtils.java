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

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.function.Function;

import org.springframework.security.core.annotation.AnnotationSynthesizers;

/**
 * A collection of utility methods that check for, and error on, conflicting annotations.
 * This is specifically important for Spring Security annotations which are not designed
 * to be repeatable.
 *
 * <p>
 * There are numerous ways that two annotations of the same type may be attached to the
 * same method. For example, a class may implement a method defined in two separate
 * interfaces. If both of those interfaces have a {@code @PreAuthorize} annotation, then
 * it's unclear which {@code @PreAuthorize} expression Spring Security should use.
 *
 * <p>
 * Another way is when one of Spring Security's annotations is used as a meta-annotation.
 * In that case, two custom annotations can be declared, each with their own
 * {@code @PreAuthorize} declaration. If both custom annotations are used on the same
 * method, then it's unclear which {@code @PreAuthorize} expression Spring Security should
 * use.
 *
 * @author Josh Cummings
 * @author Sam Brannen
 */
final class AuthorizationAnnotationUtils {

	static <A extends Annotation> Function<AnnotatedElement, A> withDefaults(Class<A> type) {
		return AnnotationSynthesizers.requireUnique(type)::synthesize;
	}

	static <A extends Annotation> A findUniqueAnnotation(Method method, Class<A> annotationType) {
		return AnnotationSynthesizers.requireUnique(annotationType).synthesize(method);
	}

	static <A extends Annotation> A findUniqueAnnotation(Class<?> type, Class<A> annotationType) {
		return AnnotationSynthesizers.requireUnique(annotationType).synthesize(type);
	}

	private AuthorizationAnnotationUtils() {

	}

}
