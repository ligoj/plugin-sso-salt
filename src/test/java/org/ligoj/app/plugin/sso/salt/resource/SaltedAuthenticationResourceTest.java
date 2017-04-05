package org.ligoj.app.plugin.sso.salt.resource;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.transaction.Transactional;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ligoj.app.AbstractAppTest;
import org.ligoj.app.iam.IUserRepository;
import org.ligoj.app.iam.IamConfiguration;
import org.ligoj.app.iam.IamProvider;
import org.ligoj.bootstrap.model.system.SystemConfiguration;
import org.mockito.Mockito;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Test class of {@link SaltedAuthenticationResource}
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:/META-INF/spring/application-context-test.xml")
@Transactional
@Rollback
public class SaltedAuthenticationResourceTest extends AbstractAppTest {

	private SaltedAuthenticationResource resource;
	private IUserRepository userRepository;

	@Before
	public void prepareData() throws IOException {
		// Only with Spring context
		persistEntities("csv", new Class[] { SystemConfiguration.class }, StandardCharsets.UTF_8.name());

		resource = new SaltedAuthenticationResource();
		applicationContext.getAutowireCapableBeanFactory().autowireBean(resource);
		resource.iamProvider = Mockito.mock(IamProvider.class);
		final IamConfiguration configuration = Mockito.mock(IamConfiguration.class);
		Mockito.when(resource.iamProvider.getConfiguration()).thenReturn(configuration);
		userRepository = Mockito.mock(IUserRepository.class);
		Mockito.when(configuration.getUserRepository()).thenReturn(userRepository);
	}

	@Test
	public void testGetToken() throws Exception {
		Mockito.when(userRepository.getToken("jdupont")).thenReturn("pwd");
		Assert.assertNotNull(StringUtils.trimToNull(resource.getSsoToken("jdupont")));
	}

	@Test
	public void testGetTokenFromUser() throws Exception {
		Mockito.when(userRepository.getToken("any")).thenReturn(null);
		Mockito.when(userRepository.getToken(null)).thenReturn(null);
		Assert.assertNull(resource.getSsoToken("any"));
		Assert.assertNull(resource.getSsoToken(null));
	}

	@Test(expected = AccessDeniedException.class)
	public void testCheckEmptyToken() throws Exception {
		Assert.assertNull(resource.checkSsoToken(null));
		Assert.assertNull(resource.checkSsoToken(""));
	}

	@Test
	public void testValidToken() throws Exception {
		Mockito.when(userRepository.getToken("jdupont")).thenReturn("pwd");
		Assert.assertEquals("jdupont", resource.checkSsoToken(resource.getSsoToken("jdupont")));
	}

	@Test(expected = AccessDeniedException.class)
	public void checkSsoTokenPasswordChanged() throws Exception {
		Mockito.when(userRepository.getToken("hdurant")).thenReturn("old-pwd", "new-pwd");
		final String token = resource.getSsoToken("hdurant");
		resource.checkSsoToken(token);
	}

	@Test(expected = AccessDeniedException.class)
	public void checkSsoTokenTooOldToken() throws Exception {
		Mockito.when(userRepository.getToken("mmartin")).thenReturn("pwd");
		final String token = getOldSsoToken("mmartin", "pwd");
		resource.checkSsoToken(token);
	}

	@Test(expected = AccessDeniedException.class)
	public void testNotExist() throws Exception {
		Mockito.when(userRepository.getToken("jdoe4")).thenReturn(null);
		resource.checkSsoToken(null);
	}

	/**
	 * Return SSO token to use in cross site parameters valid for 30 minutes.
	 * 
	 * @param login
	 *            The login of the user
	 * @param userKey
	 *            The key of the user
	 * @return SSO token to use as cross site parameter.
	 */
	private String getOldSsoToken(final String login, final String userKey) throws Exception {
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
	public void getKey() {
		Assert.assertEquals("feature:sso:salt", resource.getKey());
	}
}
