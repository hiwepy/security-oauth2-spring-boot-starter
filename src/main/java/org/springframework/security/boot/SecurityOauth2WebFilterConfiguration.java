package org.springframework.security.boot;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.ajax.AjaxAwareAuthenticationFailureHandler;
import org.springframework.security.boot.jwt.authentication.ajax.AjaxAwareAuthenticationSuccessHandler;
import org.springframework.security.boot.jwt.authentication.ajax.AjaxUsernamePasswordAuthenticationFilter;
import org.springframework.security.boot.jwt.authentication.jwt.JwtTokenAuthenticationFilter;
import org.springframework.security.boot.jwt.authentication.jwt.SkipPathRequestMatcher;
import org.springframework.security.boot.jwt.authentication.jwt.extractor.TokenExtractor;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration",
	"org.springframework.security.boot.SecurityBizWebFilterConfiguration"   // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityOauth2Properties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityOauth2Properties.class, SecurityBizProperties.class, ServerProperties.class })
public class SecurityOauth2WebFilterConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private SecurityOauth2Properties jwtProperties;
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private ServerProperties serverProperties;


	@Bean
	protected BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
		return new WebAuthenticationDetailsSource();
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationSuccessHandler successHandler(ObjectMapper mapper) {
		
		// Ajax Login
		if(bizProperties.isLoginAjax()) {
			AjaxAwareAuthenticationSuccessHandler successHandler = new AjaxAwareAuthenticationSuccessHandler(mapper, jwtProperties);
			return successHandler;
		}
		// Form Login
		else {
			SimpleUrlAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
			successHandler.setDefaultTargetUrl(bizProperties.getSuccessUrl());
			return successHandler;
		}
		
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationFailureHandler failureHandler() {
		// Ajax Login
		if(bizProperties.isLoginAjax()) {
			return new AjaxAwareAuthenticationFailureHandler(bizProperties.getFailureUrl());
		}
		// Form Login
		else {
			return new SimpleUrlAuthenticationFailureHandler(bizProperties.getFailureUrl());
		}
	}

	@Bean
	@ConditionalOnMissingBean
	public SessionAuthenticationStrategy sessionStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}

	@Bean
	@ConditionalOnMissingBean
	public RememberMeServices rememberMeServices() {
		return new NullRememberMeServices();
	}

	public static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";
    public static final String FORM_BASED_LOGIN_ENTRY_POINT = "/api/auth/login";
    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";
    public static final String TOKEN_REFRESH_ENTRY_POINT = "/api/auth/token";
    
    @Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return new ObjectMapper();
	}
    
    @Bean
	@ConditionalOnMissingBean
	public AjaxUsernamePasswordAuthenticationFilter jwtAjaxLoginProcessingFilter(AuthenticationFailureHandler failureHandler,
			AuthenticationManager authenticationManager, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy, ObjectMapper objectMapper) throws Exception {
        //AjaxUsernamePasswordAuthenticationFilter filter = new AjaxUsernamePasswordAuthenticationFilter(FORM_BASED_LOGIN_ENTRY_POINT, successHandler, failureHandler, objectMapper);
        //filter.setAuthenticationManager(authenticationManager);
        return null;
    }
    
    @Bean
	@ConditionalOnMissingBean
	public JwtTokenAuthenticationFilter jwtTokenAuthenticationProcessingFilter(
    		AuthenticationFailureHandler failureHandler,
    		TokenExtractor tokenExtractor,
			AuthenticationManager authenticationManager, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy) throws Exception {
    	
        List<String> pathsToSkip = Arrays.asList(TOKEN_REFRESH_ENTRY_POINT, FORM_BASED_LOGIN_ENTRY_POINT);
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, TOKEN_BASED_AUTH_ENTRY_POINT);
        
        JwtTokenAuthenticationFilter authenticationFilter  = new JwtTokenAuthenticationFilter(failureHandler, tokenExtractor, matcher);
        
        authenticationFilter.setAllowSessionCreation(false);
		authenticationFilter.setApplicationEventPublisher(publisher);
		authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		authenticationFilter.setAuthenticationFailureHandler(failureHandler);
		authenticationFilter.setAuthenticationManager(authenticationManager);
		authenticationFilter.setAuthenticationSuccessHandler(successHandler);
		authenticationFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getLoginUrlPatterns())) {
			authenticationFilter.setFilterProcessesUrl(bizProperties.getLoginUrlPatterns());
		}
		// authenticationFilter.setMessageSource(messageSource);
		authenticationFilter.setRememberMeServices(rememberMeServices);
		authenticationFilter.setSessionAuthenticationStrategy(sessionStrategy);
        
        return authenticationFilter;
    }
     
	
	@Bean
	@ConditionalOnMissingBean
	public AbstractAuthenticationProcessingFilter authenticationFilter(AuthenticationFailureHandler failureHandler,
			AuthenticationManager authenticationManager, ApplicationEventPublisher publisher,
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource,
			AuthenticationSuccessHandler successHandler, RememberMeServices rememberMeServices,
			SessionAuthenticationStrategy sessionStrategy) {

		UsernamePasswordAuthenticationFilter authenticationFilter = new UsernamePasswordAuthenticationFilter();

		authenticationFilter.setAllowSessionCreation(bizProperties.isAllowSessionCreation());
		authenticationFilter.setApplicationEventPublisher(publisher);
		authenticationFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
		authenticationFilter.setAuthenticationFailureHandler(failureHandler);
		authenticationFilter.setAuthenticationManager(authenticationManager);
		authenticationFilter.setAuthenticationSuccessHandler(successHandler);
		authenticationFilter.setContinueChainBeforeSuccessfulAuthentication(false);
		if (StringUtils.hasText(bizProperties.getLoginUrlPatterns())) {
			authenticationFilter.setFilterProcessesUrl(bizProperties.getLoginUrlPatterns());
		}
		// authenticationFilter.setMessageSource(messageSource);
		authenticationFilter.setPasswordParameter(bizProperties.getPasswordParameter());
		authenticationFilter.setPostOnly(bizProperties.isPostOnly());
		authenticationFilter.setRememberMeServices(rememberMeServices);
		authenticationFilter.setSessionAuthenticationStrategy(sessionStrategy);
		authenticationFilter.setUsernameParameter(bizProperties.getUsernameParameter());

		return authenticationFilter;
	}

	@Bean
	@ConditionalOnMissingBean
	public AuthenticationEntryPoint authenticationEntryPoint() {
		
		LoginUrlAuthenticationEntryPoint entryPoint = new LoginUrlAuthenticationEntryPoint(bizProperties.getLoginUrl());
		entryPoint.setForceHttps(bizProperties.isForceHttps());
		entryPoint.setUseForward(bizProperties.isUseForward());
		
		return entryPoint;
	}
	
	/**
	 * 系统登录注销过滤器；默认：org.springframework.security.web.authentication.logout.LogoutFilter
	 */
	@Bean
	@ConditionalOnMissingBean
	public LogoutFilter logoutFilter() {
		// 登录注销后的重定向地址：直接进入登录页面
		LogoutFilter logoutFilter = new LogoutFilter(bizProperties.getLoginUrl(), new SecurityContextLogoutHandler());
		logoutFilter.setFilterProcessesUrl(bizProperties.getLogoutUrlPatterns());
		return logoutFilter;
	}

	/*@Bean
	public FilterRegistrationBean<HttpParamsFilter> httpParamsFilter() {
		FilterRegistrationBean<HttpParamsFilter> filterRegistrationBean = new FilterRegistrationBean<HttpParamsFilter>();
		filterRegistrationBean.setFilter(new HttpParamsFilter());
		filterRegistrationBean.setOrder(-999);
		filterRegistrationBean.addUrlPatterns("/");
		return filterRegistrationBean;
	}*/

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
