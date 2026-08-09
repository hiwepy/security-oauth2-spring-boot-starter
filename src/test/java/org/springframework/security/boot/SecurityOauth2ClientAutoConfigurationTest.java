package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link SecurityOauth2ClientAutoConfiguration}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SecurityOauth2ClientAutoConfiguration Tests")
class SecurityOauth2ClientAutoConfigurationTest {

    private final SecurityOauth2ClientAutoConfiguration config = new SecurityOauth2ClientAutoConfiguration();

    @Test
    @DisplayName("Auto-configuration class can be instantiated")
    void testInstantiation() {
        assertThat(config).isNotNull();
    }

    @Test
    @DisplayName("authorizedClientRepository bean is created")
    void testAuthorizedClientRepository() {
        OAuth2AuthorizedClientService service = mock(OAuth2AuthorizedClientService.class);
        OAuth2AuthorizedClientRepository repository = config.authorizedClientRepository(service);
        assertThat(repository).isNotNull();
    }
}
