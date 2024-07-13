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

package org.springframework.security.core.annotation;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.core.annotation.MergedAnnotation;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.core.annotation.RepeatableContainers;
import org.springframework.util.Assert;

/**
 * A strategy for synthesizing an annotation from an {@link AnnotatedElement} that
 * supports meta-annotations, like the following:
 *
 * <pre>
 *	&#64;PreAuthorize("hasRole('ROLE_ADMIN')")
 *	public @annotation HasRole {
 *	}
 * </pre>
 *
 * <p>
 * In that case, you can use an {@link UniqueMergedAnnotationSynthesizer} of type
 * {@link org.springframework.security.access.prepost.PreAuthorize} to synthesize any
 * {@code @HasRole} annotation found on a given {@link AnnotatedElement}.
 *
 * <p>
 * Note that in all cases, Spring Security does not allow for repeatable annotations. As
 * such, this class errors if a repeat is discovered.
 *
 * <p>
 * If the given annotation can be applied to types, this class will search for annotations
 * across the entire {@link MergedAnnotations.SearchStrategy type hierarchy}; otherwise,
 * it will only look for annotations {@link MergedAnnotations.SearchStrategy directly}
 * attributed to the element.
 *
 * <p>
 * Since the process of synthesis is expensive, it is recommended to cache the synthesized
 * result to prevent multiple computations.
 *
 * @param <A> the annotation type
 * @author Josh Cummings
 * @since 6.4
 */
final class UniqueMergedAnnotationSynthesizer<A extends Annotation> implements AnnotationSynthesizer<A> {

	private final List<Class<A>> types;

	UniqueMergedAnnotationSynthesizer(Class<A> type) {
		Assert.notNull(type, "type cannot be null");
		this.types = List.of(type);
	}

	UniqueMergedAnnotationSynthesizer(List<Class<A>> types) {
		Assert.notNull(types, "types cannot be null");
		this.types = types;
	}

	@Override
	public MergedAnnotation<A> merge(AnnotatedElement element) {
		if (element instanceof Parameter) {
			MergedAnnotations mergedAnnotations = MergedAnnotations.from(element,
					MergedAnnotations.SearchStrategy.DIRECT, RepeatableContainers.none());
			List<MergedAnnotation<Annotation>> annotations = mergedAnnotations.stream()
				.filter((annotation) -> this.types.contains(annotation.getType()))
				// .map(MergedAnnotation::synthesize)
				// .distinct()
				.toList();
			return switch (annotations.size()) {
				case 0 -> null;
				case 1 -> (MergedAnnotation<A>) annotations.get(0);
				default -> throw new AnnotationConfigurationException("""
						Please ensure there is one unique annotation of type %s attributed to %s. \
						Found %d competing annotations: %s""".formatted(this.types, element, annotations.size(),
						annotations));
			};
		}
		else if (element instanceof Method method) {
			return findDistinctAnnotation(method, method.getDeclaringClass());
		}
		else {
			return findDistinctAnnotation(null, (Class<?>) element);
		}
	}

	private <A extends Annotation> MergedAnnotation<A> findDistinctAnnotation(Method method, Class<?> targetClass) {
		List<AnnotationScore<Annotation>> scores = findAnnotations(method, targetClass, new HashSet<>(), 1);
		int lowestScore = Integer.MAX_VALUE;
		List<MergedAnnotation<Annotation>> annotations = new ArrayList<>();
		for (AnnotationScore<Annotation> score : scores) {
			if (score.score < lowestScore) {
				annotations = new ArrayList<>();
				annotations.add(score.annotation);
				lowestScore = score.score;
			}
			else if (score.score == lowestScore) {
				annotations.add(score.annotation);
			}
		}
		return switch (annotations.size()) {
			case 0 -> null;
			case 1 -> (MergedAnnotation<A>) annotations.get(0);
			default -> {
				List<Annotation> synthesized = new ArrayList<>();
				for (MergedAnnotation<Annotation> annotation : annotations) {
					synthesized.add(annotation.synthesize());
				}
				throw new AnnotationConfigurationException("""
						Please ensure there is one unique annotation of type @%s attributed to %s. \
						Found %d competing annotations: %s""".formatted(this.types, method, annotations.size(),
						synthesized));
			}
		};
	}

	private List<AnnotationScore<Annotation>> findAnnotations(Method method, Class<?> declaringClass,
			Set<Class<?>> visited, int distance) {
		if (declaringClass == null || visited.contains(declaringClass) || declaringClass == Object.class) {
			return Collections.emptyList();
		}
		visited.add(declaringClass);

		Method methodToUse = methodMatching(method, declaringClass);
		if (methodToUse != null) {
			List<AnnotationScore<Annotation>> scores = findAnnotations(methodToUse, distance * 11);
			if (!scores.isEmpty()) {
				return scores;
			}
		}

		List<AnnotationScore<Annotation>> scores = findAnnotations(declaringClass, distance * 13);
		if (!scores.isEmpty()) {
			return scores;
		}

		scores.addAll(findAnnotations(methodToUse, declaringClass.getSuperclass(), visited, distance + 1));
		for (Class<?> inter : declaringClass.getInterfaces()) {
			scores.addAll(findAnnotations(methodToUse, inter, visited, distance + 1));
		}
		return scores;
	}

	private Method methodMatching(Method method, Class<?> candidate) {
		if (method == null) {
			return null;
		}
		if (method.getDeclaringClass() == candidate) {
			return method;
		}
		try {
			return candidate.getDeclaredMethod(method.getName(), method.getParameterTypes());
		}
		catch (Exception ex) {
			return method;
		}
	}

	private List<AnnotationScore<Annotation>> findAnnotations(AnnotatedElement element, int score) {
		List<MergedAnnotation<Annotation>> annotations = MergedAnnotations
			.from(element, MergedAnnotations.SearchStrategy.DIRECT, RepeatableContainers.none())
			.stream()
			.filter((annotation) -> this.types.contains(annotation.getType()))
			// .map(MergedAnnotation::synthesize)
			.toList();
		List<AnnotationScore<Annotation>> scores = new ArrayList<>();
		for (MergedAnnotation<Annotation> annotation : annotations) {
			scores.add(new AnnotationScore<>(annotation, score));
		}
		return scores;
	}

	private record AnnotationScore<A extends Annotation>(MergedAnnotation<A> annotation, int score) {
		@Override
		public String toString() {
			return this.annotation.toString();
		}
	}

}
