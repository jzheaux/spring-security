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
import java.lang.annotation.ElementType;
import java.lang.annotation.Target;
import java.lang.reflect.AnnotatedElement;
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

	private final Class<A> type;

	UniqueMergedAnnotationSynthesizer(Class<A> type) {
		Assert.notNull(type, "type cannot be null");
		this.type = type;
	}

	@Override
	public A synthesize(AnnotatedElement element) {
		MergedAnnotations.SearchStrategy searchStrategy = MergedAnnotations.SearchStrategy.DIRECT;
		Target target = this.type.getAnnotation(Target.class);
		if (Set.of(target.value()).contains(ElementType.TYPE)) {
			searchStrategy = MergedAnnotations.SearchStrategy.TYPE_HIERARCHY;
		}
		MergedAnnotations mergedAnnotations = MergedAnnotations.from(element, searchStrategy,
				RepeatableContainers.none());
		List<A> annotations = mergedAnnotations.stream(this.type)
			// .map(MergedAnnotation::withNonMergedAttributes)
			.map(MergedAnnotation::synthesize)
			.distinct()
			.toList();

		return switch (annotations.size()) {
			case 0 -> null;
			case 1 -> annotations.get(0);
			default -> throw new AnnotationConfigurationException("""
					Please ensure there is one unique annotation of type @%s attributed to %s. \
					Found %d competing annotations: %s""".formatted(this.type.getName(), element, annotations.size(),
					annotations));
		};
	}

}
