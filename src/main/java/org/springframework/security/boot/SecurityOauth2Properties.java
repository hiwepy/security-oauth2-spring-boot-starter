package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = SecurityOauth2Properties.PREFIX)
/**\n * Configuration properties for OAuth2 security.\n *\n * @author [@Loong Wan](https://github.com/loong10k)\n * @since 1.0.0\n */
public class SecurityOauth2Properties {

	public static final String PREFIX = "spring.security.oauth2";


}
