package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityOauth2ClientProperties}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SecurityOauth2ClientProperties Tests")
class SecurityOauth2ClientPropertiesTest {

    @Test
    @DisplayName("PREFIX constant has expected value")
    void testPREFIXConstant() {
        assertThat(SecurityOauth2ClientProperties.PREFIX).isEqualTo("spring.security.oauth2.client");
    }

    @Test
    @DisplayName("JWT_TOKEN_HEADER_PARAM constant has expected value")
    void testJWT_TOKEN_HEADER_PARAMConstant() {
        assertThat(SecurityOauth2ClientProperties.JWT_TOKEN_HEADER_PARAM).isEqualTo("X-Authorization");
    }

    @Test
    @DisplayName("Default values are correct")
    void testDefaultValues() {
        SecurityOauth2ClientProperties props = new SecurityOauth2ClientProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.getTokenHeaderName()).isEqualTo("X-Authorization");
        assertThat(props.getTokenExpirationTime()).isNull();
        assertThat(props.getTokenIssuer()).isNull();
        assertThat(props.getTokenSigningKey()).isNull();
        assertThat(props.getRefreshTokenExpTime()).isNull();
        assertThat(props.getSecret()).isNull();
        assertThat(props.getAccessTokenExpiration()).isNull();
        assertThat(props.getRefreshTokenExpiration()).isNull();
    }

    @Test
    @DisplayName("enabled getter/setter works")
    void testEnabled() {
        SecurityOauth2ClientProperties props = new SecurityOauth2ClientProperties();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("tokenHeaderName getter/setter works")
    void testTokenHeaderName() {
        SecurityOauth2ClientProperties props = new SecurityOauth2ClientProperties();
        props.setTokenHeaderName("Authorization");
        assertThat(props.getTokenHeaderName()).isEqualTo("Authorization");
    }

    @Test
    @DisplayName("tokenExpirationTime getter/setter works")
    void testTokenExpirationTime() {
        SecurityOauth2ClientProperties props = new SecurityOauth2ClientProperties();
        props.setTokenExpirationTime(3600);
        assertThat(props.getTokenExpirationTime()).isEqualTo(3600);
    }

    @Test
    @DisplayName("tokenIssuer getter/setter works")
    void testTokenIssuer() {
        SecurityOauth2ClientProperties props = new SecurityOauth2ClientProperties();
        props.setTokenIssuer("issuer");
        assertThat(props.getTokenIssuer()).isEqualTo("issuer");
    }

    @Test
    @DisplayName("tokenSigningKey getter/setter works")
    void testTokenSigningKey() {
        SecurityOauth2ClientProperties props = new SecurityOauth2ClientProperties();
        props.setTokenSigningKey("key");
        assertThat(props.getTokenSigningKey()).isEqualTo("key");
    }

    @Test
    @DisplayName("refreshTokenExpTime getter/setter works")
    void testRefreshTokenExpTime() {
        SecurityOauth2ClientProperties props = new SecurityOauth2ClientProperties();
        props.setRefreshTokenExpTime(7200);
        assertThat(props.getRefreshTokenExpTime()).isEqualTo(7200);
    }

    @Test
    @DisplayName("secret getter/setter works")
    void testSecret() {
        SecurityOauth2ClientProperties props = new SecurityOauth2ClientProperties();
        props.setSecret("my_secret");
        assertThat(props.getSecret()).isEqualTo("my_secret");
    }

    @Test
    @DisplayName("accessTokenExpiration getter/setter works")
    void testAccessTokenExpiration() {
        SecurityOauth2ClientProperties props = new SecurityOauth2ClientProperties();
        props.setAccessTokenExpiration(3600L);
        assertThat(props.getAccessTokenExpiration()).isEqualTo(3600L);
    }

    @Test
    @DisplayName("refreshTokenExpiration getter/setter works")
    void testRefreshTokenExpiration() {
        SecurityOauth2ClientProperties props = new SecurityOauth2ClientProperties();
        props.setRefreshTokenExpiration(7200L);
        assertThat(props.getRefreshTokenExpiration()).isEqualTo(7200L);
    }
}
