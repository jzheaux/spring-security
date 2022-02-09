package org.springframework.security.core.context;

import java.util.Collection;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;

public class SecurityContextChangedListenersPostProcessor implements BeanDefinitionRegistryPostProcessor {

	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

	}

	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
		if (registry instanceof ConfigurableListableBeanFactory) {
			String[] names = ((ConfigurableListableBeanFactory) registry).getBeanNamesForType(SecurityContextHolderStrategy.class);
			if (names.length > 0) {
				return;
			}
			Collection<SecurityContextChangedListener> listeners = ((ConfigurableListableBeanFactory) registry)
					.getBeansOfType(SecurityContextChangedListener.class).values();
			SecurityContextHolderStrategy listeningStrategy = new ListeningSecurityContextHolderStrategy(listeners);
			BeanDefinition definition = BeanDefinitionBuilder
					.rootBeanDefinition(SecurityContextHolderStrategy.class, () -> listeningStrategy).getBeanDefinition();
			registry.registerBeanDefinition("securityContextHolderStrategy", definition);
		}
	}
}
