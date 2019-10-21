package org.springframework.security.boot;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

@Configuration
@AutoConfigureBefore(name = { "org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration",
		"org.springframework.security.boot.SecurityBizWebFilterConfiguration" // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityOauth2Properties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityOauth2Properties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityOauth2ClientFilterConfiguration<OAuth2RestTemplate> extends WebSecurityConfigurerAdapter implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private SecurityOauth2Properties jwtProperties;
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;
	
	// 自动注入UserDetailsService
    @Autowired
    private UserDetailsService baseUserDetailService;
    
	@Bean
	protected BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	/*
	 * @Bean public OAuth2RestTemplate restTemplate(OAuth2ClientContext
	 * oauth2ClientContext) { return new OAuth2RestTemplate( oauth2ClientContext); }
	 */
	
	@Bean
	@ConditionalOnMissingBean
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 8)
	public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
		return new HttpSessionOAuth2AuthorizationRequestRepository();
	}

	
	
	/*
	 * @Autowired private OAuth2ClientContext oauth2Context;
	 * 
	 * @Bean public OAuth2RestTemplate sparklrRestTemplate() {
	 
	@Bean
	@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
	public OAuth2RestOperations restTemplate() {
		OAuth2RestTemplate template = new OAuth2RestTemplate(resource(),
				new DefaultOAuth2ClientContext(accessTokenRequest));
		AccessTokenProviderChain provider = new AccessTokenProviderChain(
				Arrays.asList(new AuthorizationCodeAccessTokenProvider()));
		provider.setClientTokenServices(clientTokenServices());
		return template;
	}*/

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        //auth.authenticationProvider(ajaxAuthenticationProvider);
       // auth.authenticationProvider(jwtAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    }
     
     
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}
 
}
