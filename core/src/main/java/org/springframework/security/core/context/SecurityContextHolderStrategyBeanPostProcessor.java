package org.springframework.security.core.context;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;

public final class SecurityContextHolderStrategyBeanPostProcessor implements BeanFactoryPostProcessor {
	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
		String[] names = beanFactory.getBeanNamesForType(SecurityContextHolderStrategy.class);
		if (names.length > 0) {
			SecurityContextHolder.setContextHolderStrategy(beanFactory.getBean(SecurityContextHolderStrategy.class));
		}
	}
}
