package org.springframework.security.boot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.scribejava.core.extractors.TokenExtractor;

// http://blog.csdn.net/change_on/article/details/76302161
@Configuration
@AutoConfigureBefore( name = {
	"org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration",
	"org.springframework.security.boot.SecurityBizWebAutoConfiguration"  // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityOauth2Properties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityOauth2Properties.class })
@EnableWebSecurity
public class SecurityOauth2WebAutoConfiguration extends WebSecurityConfigurerAdapter {

	 
	    public static final String FORM_BASED_LOGIN_ENTRY_POINT = "/authz/login";
	    public static final String TOKEN_BASED_AUTH_ENTRY_POINT = "/api/**";
	    public static final String TOKEN_REFRESH_ENTRY_POINT = "/authz/token";
	    
    
	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    
    @Autowired
    private AbstractAuthenticationProcessingFilter authenticationFilter;
    @Autowired
    private LogoutFilter logoutFilter;
    
    @Autowired
    private InvalidSessionStrategy invalidSessionStrategy;
    @Autowired
    private SessionInformationExpiredStrategy expiredSessionStrategy;
    
    @Autowired 
    private RestAuthenticationEntryPoint authenticationEntryPoint;
    @Autowired 
    private AuthenticationSuccessHandler successHandler;
    @Autowired 
    private AuthenticationFailureHandler failureHandler;
    @Autowired 
    private AjaxAuthenticationProvider ajaxAuthenticationProvider;
    @Autowired 
    private JwtAuthenticationProvider jwtAuthenticationProvider;
    @Autowired 
    private TokenExtractor tokenExtractor;
    @Autowired 
    private AuthenticationManager authenticationManager;
    @Autowired 
    private ObjectMapper objectMapper;
    
    @Autowired 
    private AjaxUsernamePasswordAuthenticationFilter jwtAjaxLoginProcessingFilter;
    @Autowired 
    private JwtTokenAuthenticationFilter jwtTokenAuthenticationProcessingFilter;
    
    @Bean
	@ConditionalOnMissingBean
    public InvalidSessionStrategy invalidSessionStrategy(){
		return new SimpleRedirectInvalidSessionStrategy(bizProperties.getRedirectUrl());
	}
    
    @Bean
	@ConditionalOnMissingBean
    public SessionInformationExpiredStrategy expiredSessionStrategy(){
		return new SimpleRedirectSessionInformationExpiredStrategy(bizProperties.getExpiredUrl());
	}
    
    /*@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable().authorizeRequests()
                .antMatchers(HttpMethod.POST, "/users/signup").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(new JWTLoginFilter(authenticationManager()))
                .addFilter(new JwtAuthenticationFilter(authenticationManager()));
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }
    */
    
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(ajaxAuthenticationProvider);
        auth.authenticationProvider(jwtAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	http
        .csrf().disable() // We don't need CSRF for JWT based authentication
        .exceptionHandling()
        .authenticationEntryPoint(this.authenticationEntryPoint)
        
        .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        .and()
            .authorizeRequests()
                .antMatchers(bizProperties.getLoginUrlPatterns()).permitAll() // Login end-point
                .antMatchers(TOKEN_REFRESH_ENTRY_POINT).permitAll() // Token refresh end-point
                .antMatchers("/console").permitAll() // H2 Console Dash-board - only for testing
        .and()
            .authorizeRequests()
                .antMatchers(TOKEN_BASED_AUTH_ENTRY_POINT).authenticated() // Protected API End-points
        .and()
            .addFilterBefore(new CustomCorsFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAjaxLoginProcessingFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtTokenAuthenticationProcessingFilter, UsernamePasswordAuthenticationFilter.class);
    }
    
   /* @Override
    protected void configure(HttpSecurity http) throws Exception {
		
		HeadersConfigurer<HttpSecurity> headers = http.headers();
        
		if(null != bizProperties.getReferrerPolicy()) {
			headers.referrerPolicy(bizProperties.getReferrerPolicy()).and();
		}
        
		if(null != bizProperties.getFrameOptions()) {
			headers.frameOptions().disable();
		}
        
        
        http.csrf().disable();

        http.authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .antMatchers("/static/**").permitAll() 	// 不拦截静态资源
                .antMatchers("/api/**").permitAll()  	// 不拦截对外API
                    .anyRequest().authenticated();  	// 所有资源都需要登陆后才可以访问。

        http.logout().permitAll();  // 不拦截注销

        http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint);

        http.servletApi().disable();

        SessionManagementConfigurer<HttpSecurity> sessionManagement = http.sessionManagement();
        
        sessionManagement.enableSessionUrlRewriting(false)
        .invalidSessionStrategy(invalidSessionStrategy)
        .invalidSessionUrl(bizProperties.getRedirectUrl())
        .sessionAuthenticationErrorUrl(bizProperties.getFailureUrl())
        //.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        
        if(bizProperties.isMultipleSession()) {
        	sessionManagement.maximumSessions(bizProperties.getMaximumSessions()).expiredSessionStrategy(expiredSessionStrategy).expiredUrl(bizProperties.getExpiredUrl()).maxSessionsPreventsLogin(bizProperties.isMaxSessionsPreventsLogin());
        }
        
        http.addFilter(authenticationFilter)
                .addFilterBefore(logoutFilter, LogoutFilter.class);
        
        // 关闭csrf验证
        http.csrf().disable()
                // 对请求进行认证
                .authorizeRequests()
                // 所有 / 的所有请求 都放行
                .antMatchers("/").permitAll()
                // 所有 /login 的POST请求 都放行
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                // 权限检查
                .antMatchers("/hello").hasAuthority("AUTH_WRITE")
                // 角色检查
                .antMatchers("/world").hasRole("ADMIN")
                // 所有请求需要身份认证
                .anyRequest().authenticated()
            .and()
                // 添加一个过滤器 所有访问 /login 的请求交给 JWTLoginFilter 来处理 这个类处理所有的JWT相关内容
                .addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                // 添加一个过滤器验证其他请求的Token是否合法
                .addFilterBefore(new JWTAuthenticationFilter(),
                        UsernamePasswordAuthenticationFilter.class);
        
        
        
        
        http.antMatcher("/**");
    }*/

}
