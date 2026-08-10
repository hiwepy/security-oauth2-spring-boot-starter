package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityOauth2ClientFilterConfiguration}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityOauth2ClientFilterConfiguration Tests")
class SecurityOauth2ClientFilterConfigurationTest {

    private final SecurityOauth2ClientFilterConfiguration<?> config = new SecurityOauth2ClientFilterConfiguration<>();

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        assertThat(config).isNotNull();
    }

    @Test
    @DisplayName("passwordEncoder bean is created")
    void testPasswordEncoder() {
        BCryptPasswordEncoder encoder = config.passwordEncoder();
        assertThat(encoder).isNotNull();
    }

    @Test
    @DisplayName("authorizationRequestRepository bean is created")
    void testAuthorizationRequestRepository() {
        AuthorizationRequestRepository<OAuth2AuthorizationRequest> repository = config.authorizationRequestRepository();
        assertThat(repository).isNotNull();
    }
}
