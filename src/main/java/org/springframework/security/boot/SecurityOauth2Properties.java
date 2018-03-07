package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = SecurityOauth2Properties.PREFIX)
public class SecurityOauth2Properties {

	public static final String PREFIX = "spring.security.pac4j";
	public static final String JWT_TOKEN_HEADER_PARAM = "X-Authorization";
	
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
    
    public String getTokenHeaderName() {
		return tokenHeaderName;
	}

	public void setTokenHeaderName(String tokenHeaderName) {
		this.tokenHeaderName = tokenHeaderName;
	}

	public Integer getRefreshTokenExpTime() {
        return refreshTokenExpTime;
    }

    public void setRefreshTokenExpTime(Integer refreshTokenExpTime) {
        this.refreshTokenExpTime = refreshTokenExpTime;
    }

    public Integer getTokenExpirationTime() {
        return tokenExpirationTime;
    }
    
    public void setTokenExpirationTime(Integer tokenExpirationTime) {
        this.tokenExpirationTime = tokenExpirationTime;
    }
    
    public String getTokenIssuer() {
        return tokenIssuer;
    }
    public void setTokenIssuer(String tokenIssuer) {
        this.tokenIssuer = tokenIssuer;
    }
    
    public String getTokenSigningKey() {
        return tokenSigningKey;
    }
    
    public void setTokenSigningKey(String tokenSigningKey) {
        this.tokenSigningKey = tokenSigningKey;
    }

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public Long getAccessTokenExpiration() {
		return accessTokenExpiration;
	}

	public void setAccessTokenExpiration(Long accessTokenExpiration) {
		this.accessTokenExpiration = accessTokenExpiration;
	}

	public Long getRefreshTokenExpiration() {
		return refreshTokenExpiration;
	}

	public void setRefreshTokenExpiration(Long refreshTokenExpiration) {
		this.refreshTokenExpiration = refreshTokenExpiration;
	}
    
    

}
