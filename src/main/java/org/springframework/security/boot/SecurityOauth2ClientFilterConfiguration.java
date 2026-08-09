package org.springframework.security.boot;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@AutoConfigureBefore(name = {
		"org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterAutoConfiguration",
		"org.springframework.security.boot.SecurityBizWebFilterConfiguration"
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityOauth2Properties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityOauth2Properties.class, SecurityBizProperties.class })
/**
 * Filter configuration for OAuth2 client security.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class SecurityOauth2ClientFilterConfiguration<OAuth2RestTemplate> implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private SecurityOauth2Properties jwtProperties;
	@Autowired
	private SecurityBizProperties bizProperties;

	@Autowired
	private UserDetailsService baseUserDetailService;

	@Bean
	protected BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@ConditionalOnMissingBean
	@Order(8)
	public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
		return new HttpSessionOAuth2AuthorizationRequestRepository();
	}

	@Bean
	@Order(8)
	SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
		return http.build();
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

}
