package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * <p>Configuration properties.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = SecurityOauth2ClientProperties.PREFIX)
public class SecurityOauth2ClientProperties {
	
	public static final String PREFIX = "spring.security.oauth2.client";
	public static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";
	
	/**
	 * Enable Security OAuth2 Client.
	 */
	private boolean enabled = false;
	
	/** Specifies the name of the header on where to find the token (i.e. X-Authorization). */
	private String tokenHeaderName = JWT_TOKEN_HEADER_PARAM;
	
    /**
     * {@link JwtToken} will expire after this time.
     */
    private Integer tokenExpirationTime;

    /**
     * Token issuer. 
     */
    private String tokenIssuer;
    
    /**
     * Key is used to sign {@link JwtToken}.
     */
    private String tokenSigningKey;
    
    /**
     * {@link JwtToken} can be refreshed during this timeframe.
     */
    private Integer refreshTokenExpTime;
    
    private String secret;

    private Long accessTokenExpiration;

    private Long refreshTokenExpiration;
    
    /**
     * Returns the enabled.
     *
     * @return the enabled
     */
    public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Sets the enabled.
	 *
	 * @param enabled the enabled
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * Returns the token header name.
	 *
	 * @return the token header name
	 */
	public String getTokenHeaderName() {
		return tokenHeaderName;
	}

	/**
	 * Sets the token header name.
	 *
	 * @param tokenHeaderName the token header name
	 */
	public void setTokenHeaderName(String tokenHeaderName) {
		this.tokenHeaderName = tokenHeaderName;
	}

	/**
	 * Returns the refresh token exp time.
	 *
	 * @return the refresh token exp time
	 */
	public Integer getRefreshTokenExpTime() {
        return refreshTokenExpTime;
    }

    /**
     * Sets the refresh token exp time.
     *
     * @param refreshTokenExpTime the refresh token exp time
     */
    public void setRefreshTokenExpTime(Integer refreshTokenExpTime) {
        this.refreshTokenExpTime = refreshTokenExpTime;
    }

    /**
     * Returns the token expiration time.
     *
     * @return the token expiration time
     */
    public Integer getTokenExpirationTime() {
        return tokenExpirationTime;
    }
    
    /**
     * Sets the token expiration time.
     *
     * @param tokenExpirationTime the token expiration time
     */
    public void setTokenExpirationTime(Integer tokenExpirationTime) {
        this.tokenExpirationTime = tokenExpirationTime;
    }
    
    /**
     * Returns the token issuer.
     *
     * @return the token issuer
     */
    public String getTokenIssuer() {
        return tokenIssuer;
    }
    /**
     * Sets the token issuer.
     *
     * @param tokenIssuer the token issuer
     */
    public void setTokenIssuer(String tokenIssuer) {
        this.tokenIssuer = tokenIssuer;
    }
    
    /**
     * Returns the token signing key.
     *
     * @return the token signing key
     */
    public String getTokenSigningKey() {
        return tokenSigningKey;
    }
    
    /**
     * Sets the token signing key.
     *
     * @param tokenSigningKey the token signing key
     */
    public void setTokenSigningKey(String tokenSigningKey) {
        this.tokenSigningKey = tokenSigningKey;
    }

	/**
	 * Returns the secret.
	 *
	 * @return the secret
	 */
	public String getSecret() {
		return secret;
	}

	/**
	 * Sets the secret.
	 *
	 * @param secret the secret
	 */
	public void setSecret(String secret) {
		this.secret = secret;
	}

	/**
	 * Returns the access token expiration.
	 *
	 * @return the access token expiration
	 */
	public Long getAccessTokenExpiration() {
		return accessTokenExpiration;
	}

	/**
	 * Sets the access token expiration.
	 *
	 * @param accessTokenExpiration the access token expiration
	 */
	public void setAccessTokenExpiration(Long accessTokenExpiration) {
		this.accessTokenExpiration = accessTokenExpiration;
	}

	/**
	 * Returns the refresh token expiration.
	 *
	 * @return the refresh token expiration
	 */
	public Long getRefreshTokenExpiration() {
		return refreshTokenExpiration;
	}

	/**
	 * Sets the refresh token expiration.
	 *
	 * @param refreshTokenExpiration the refresh token expiration
	 */
	public void setRefreshTokenExpiration(Long refreshTokenExpiration) {
		this.refreshTokenExpiration = refreshTokenExpiration;
	}
    
    

}
