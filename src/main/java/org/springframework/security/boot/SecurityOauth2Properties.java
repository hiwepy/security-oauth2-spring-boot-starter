package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = SecurityOauth2Properties.PREFIX)
public class SecurityOauth2Properties {

	public static final String PREFIX = "spring.security.oauth2";


}
