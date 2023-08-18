/*
 * Licensed under MIT (https://github.com/ligoj/ligoj/blob/master/LICENSE)
 */
package org.ligoj.app.plugin.sso.salt.resource;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import jakarta.transaction.Transactional;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.ligoj.app.AbstractAppTest;
import org.ligoj.app.iam.IUserRepository;
import org.ligoj.app.iam.IamConfiguration;
import org.ligoj.app.iam.IamProvider;
import org.ligoj.bootstrap.model.system.SystemConfiguration;
import org.mockito.Mockito;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Test class of {@link SaltedAuthenticationResource}
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(locations = "classpath:/META-INF/spring/application-context-test.xml")
@Transactional
@Rollback
class SaltedAuthenticationResourceTest extends AbstractAppTest {

	private SaltedAuthenticationResource resource;
	private IUserRepository userRepository;

	@BeforeEach
	void prepareData() throws IOException {
		// Only with Spring context
		persistEntities("csv", new Class[]{SystemConfiguration.class}, StandardCharsets.UTF_8);

		resource = new SaltedAuthenticationResource();
		applicationContext.getAutowireCapableBeanFactory().autowireBean(resource);
		resource.iamProvider = new IamProvider[]{Mockito.mock(IamProvider.class)};
		final IamConfiguration configuration = Mockito.mock(IamConfiguration.class);
		Mockito.when(resource.iamProvider[0].getConfiguration()).thenReturn(configuration);
		userRepository = Mockito.mock(IUserRepository.class);
		Mockito.when(configuration.getUserRepository()).thenReturn(userRepository);
	}

	@Test
	void testGetToken() throws GeneralSecurityException {
		Mockito.when(userRepository.getToken("jdupont")).thenReturn("pwd");
		Assertions.assertNotNull(StringUtils.trimToNull(resource.getSsoToken("jdupont")));
	}

	@Test
	void testGetTokenFromUser() throws GeneralSecurityException {
		Mockito.when(userRepository.getToken("any")).thenReturn(null);
		Mockito.when(userRepository.getToken(null)).thenReturn(null);
		Assertions.assertNull(resource.getSsoToken("any"));
		Assertions.assertNull(resource.getSsoToken(null));
	}

	@Test
	void testCheckEmptyToken() throws Exception {
		Assertions.assertNull(resource.checkSsoToken(null));
		Assertions.assertThrows(AccessDeniedException.class, () -> Assertions.assertNull(resource.checkSsoToken("")));
	}

	@Test
	void testValidToken() throws GeneralSecurityException {
		Mockito.when(userRepository.getToken("jdupont")).thenReturn("pwd");
		Assertions.assertEquals("jdupont", resource.checkSsoToken(resource.getSsoToken("jdupont")));
	}

	@Test
	void checkSsoTokenPasswordChanged() throws GeneralSecurityException {
		Mockito.when(userRepository.getToken("hdurant")).thenReturn("old-pwd", "new-pwd");
		final String token = resource.getSsoToken("hdurant");
		Assertions.assertThrows(AccessDeniedException.class, () -> resource.checkSsoToken(token));
	}

	@Test
	void checkSsoTokenTooOldToken() throws GeneralSecurityException {
		Mockito.when(userRepository.getToken("mmartin")).thenReturn("pwd");
		final String token = getOldSsoToken("mmartin", "pwd");
		Assertions.assertThrows(AccessDeniedException.class, () -> resource.checkSsoToken(token));
	}

	@Test
	void testNotExist() {
		Mockito.when(userRepository.getToken("jdoe4")).thenReturn(null);
		Assertions.assertThrows(AccessDeniedException.class, () -> resource.checkSsoToken(null));
	}

	/**
	 * Return SSO token to use in cross site parameters valid for 30 minutes.
	 *
	 * @param login   The login of the user
	 * @param userKey The key of the user
	 * @return SSO token to use as cross site parameter.
	 */
	private String getOldSsoToken(final String login, final String userKey) throws GeneralSecurityException {
		// Uses a secure Random not a simple Random
		final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		// Salt generation 64 bits long
		final byte[] bSalt = new byte[8];
		random.nextBytes(bSalt);
		// Digest computation
		final byte[] bDigest = resource.getHash(1000, login + userKey, bSalt);
		final String sDigest = resource.byteToBase64(bDigest);
		final String sSalt = resource.byteToBase64(bSalt);
		final long expire = System.currentTimeMillis() - DateUtils.MILLIS_PER_MINUTE * 31;

		// Generated an encrypted key, valid for 30 minutes
		return resource.encrypt(login + "|" + sDigest + "|" + sSalt + "|"
				+ new String(Base64.encodeInteger(new BigInteger(String.valueOf(expire)))), "secret");
	}

	@Test
	void getKey() {
		Assertions.assertEquals("feature:sso:salt", resource.getKey());
	}
}
