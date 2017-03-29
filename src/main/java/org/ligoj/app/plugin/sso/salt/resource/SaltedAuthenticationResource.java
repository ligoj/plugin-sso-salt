package org.ligoj.app.plugin.sso.salt.resource;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.transaction.Transactional;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.ligoj.app.api.FeaturePlugin;
import org.ligoj.app.iam.IamProvider;
import org.ligoj.bootstrap.resource.system.configuration.ConfigurationResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

/**
 * Manage SSO token for VigiReport.
 */
@Slf4j
@Path("/security/sso")
@Service
@Transactional
@Produces(MediaType.APPLICATION_JSON)
public class SaltedAuthenticationResource implements FeaturePlugin {

	/**
	 * Amount of digest iterations applied to original message to produce the
	 * target hash.
	 */
	private static final int DEFAULT_ITERATION = 1000;

	/**
	 * Cipher implementation.
	 */
	private static final String DEFAULT_IMPL = "DESede";

	/**
	 * Default timeout.
	 */
	private static final int DEFAULT_TIMEOUT = 30;

	/**
	 * Default SSO digest algorithm used for password.
	 */
	private static final String DEFAULT_DIGEST = "SHA-1";

	@Autowired
	protected IamProvider iamProvider;

	@Autowired
	private ConfigurationResource configuration;

	/**
	 * Authenticates the user with a given login and password If password and/or
	 * login is null then always returns false. If the user does not exist in
	 * the database returns false.
	 * 
	 * @param token
	 *            SSO token to validate.
	 * @return the associated trusted user name or null.
	 */
	@POST
	public String checkSsoToken(final String token) throws NoSuchAlgorithmException {
		String[] fields = new String[0];
		boolean userExist = true;

		// Secret key of DES algorithm used to generated the SSO token.
		final String ssoKey = get("sso.secret", "secret");
		try {
			fields = StringUtils.split(StringUtils.trimToEmpty(decrypt(token, ssoKey)), "|");
		} catch (final Exception e) { // NOSONAR - avoid log pollution for this
			// TIME RESISTANT ATTACK
			log.warn("Bad SSO attack attempt with token '{}'", token);
		}
		if (fields.length != 4) {
			// TIME RESISTANT ATTACK
			userExist = false;
			fields = new String[] { "0", "000000000000000000000000000=", "00000000000=", "0" };
		}
		final String login = fields[0];
		final String digest = fields[1];
		final String salt = fields[2];

		final long expire = Base64.decodeInteger(fields[3].getBytes(StandardCharsets.UTF_8)).longValue();
		String userKey = getUserKey(login);
		if (userKey == null || expire < System.currentTimeMillis()) {
			// TIME RESISTANT ATTACK
			// Computation time is equal to the time needed for a legitimate
			// user
			userExist = false;
			userKey = "0";
		}

		final byte[] bDigest = base64ToByte(digest);
		final byte[] bSalt = base64ToByte(salt);

		// Compute the new DIGEST
		final byte[] proposedDigest = getHash(get("sso.iterations", DEFAULT_ITERATION), login + userKey + expire,
				bSalt);

		final boolean digestCompare = Arrays.equals(proposedDigest, bDigest);
		if (userExist && digestCompare) {
			// Authenticated user
			return login;
		}
		throw new AccessDeniedException("");
	}

	/**
	 * Return the configuration integer value.
	 * 
	 * @param key
	 *            The configuration key name.
	 * @param defaultValue
	 *            The default integer value when <code>null</code>
	 * @return the configuration integer value or the default value.
	 */
	private int get(final String key, final int defaultValue) {
		return NumberUtils.toInt(configuration.get(key), defaultValue);
	}

	/**
	 * Return the configuration integer value.
	 * 
	 * @param key
	 *            The configuration key name.
	 * @param defaultValue
	 *            The default integer value when <code>null</code>
	 * @return the configuration integer value or the default value.
	 */
	private String get(final String key, final String defaultValue) {
		return ObjectUtils.defaultIfNull(configuration.get(key), defaultValue);
	}

	/**
	 * SSO digest algorithm used for password.
	 */
	private String getDigest() {
		return get("sso.digest", DEFAULT_DIGEST);
	}

	/**
	 * Return SSO token to use in cross site parameters valid for 30 minutes.
	 * 
	 * @param login
	 *            String The login of the user
	 * @return SSO token to use in cross site parameters.
	 */
	public String getSsoToken(final String login) throws Exception {
		final String userKey = getUserKey(login);
		if (userKey == null) {
			return null;
		}
		return getSsoToken(StringUtils.trimToEmpty(login), StringUtils.trimToEmpty(userKey));
	}

	/**
	 * Encrypt the message with the given key.
	 * 
	 * @param message
	 *            Ciphered message.
	 * @param secretKey
	 *            The secret key.
	 * @return the original message.
	 */
	protected String encrypt(final String message, final String secretKey) throws Exception { // NOSONAR
		// SSO digest algorithm used for password. This
		final MessageDigest md = MessageDigest.getInstance(getDigest());
		final byte[] digestOfPassword = md.digest(secretKey.getBytes(StandardCharsets.UTF_8));
		final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);

		// Cipher implementation.
		final String algo = get("sso.crypt", DEFAULT_IMPL);

		final SecretKey key = new SecretKeySpec(keyBytes, algo);
		final Cipher cipher = Cipher.getInstance(algo);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		final byte[] plainTextBytes = message.getBytes(StandardCharsets.UTF_8);
		final byte[] buf = cipher.doFinal(plainTextBytes);
		final byte[] base64Bytes = Base64.encodeBase64(buf);
		return new String(base64Bytes, StandardCharsets.UTF_8);
	}

	/**
	 * Decrypt the message with the given key.
	 * 
	 * @param encryptedMessage
	 *            Encrypted message.
	 * @param secretKey
	 *            The secret key.
	 * @return the original message.
	 */
	private String decrypt(final String encryptedMessage, final String secretKey) throws Exception { // NOSONAR
		final byte[] message = Base64.decodeBase64(encryptedMessage.getBytes(StandardCharsets.UTF_8));
		final MessageDigest md = MessageDigest.getInstance(getDigest());
		final byte[] digestOfPassword = md.digest(secretKey.getBytes(StandardCharsets.UTF_8));
		final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
		final String algo = get("sso.crypt", DEFAULT_IMPL);
		final SecretKey key = new SecretKeySpec(keyBytes, algo);
		final Cipher decipher = Cipher.getInstance(algo);
		decipher.init(Cipher.DECRYPT_MODE, key);
		final byte[] plainText = decipher.doFinal(message);
		return new String(plainText, StandardCharsets.UTF_8);
	}

	/**
	 * From a password, a number of iterations and a salt, returns the
	 * corresponding digest
	 * 
	 * @param iterations
	 *            The amount of iterations of the algorithm.
	 * @param password
	 *            String The password to encrypt
	 * @param salt
	 *            byte[] The salt
	 * @return byte[] The digested password
	 * @throws NoSuchAlgorithmException
	 *             If the algorithm doesn't exist
	 */
	protected byte[] getHash(final int iterations, final String password, final byte[] salt)
			throws NoSuchAlgorithmException {
		final MessageDigest digest = MessageDigest.getInstance(getDigest());
		digest.reset();
		digest.update(salt);
		byte[] input = digest.digest(password.getBytes(StandardCharsets.UTF_8));
		for (int i = 0; i < iterations; i++) {
			digest.reset();
			input = digest.digest(input);
		}
		return input;
	}

	/**
	 * From a base 64 representation, returns the corresponding byte[]
	 * 
	 * @param data
	 *            String The base64 representation
	 * @return byte[]
	 */
	protected byte[] base64ToByte(final String data) {
		return Base64.decodeBase64(data);
	}

	/**
	 * From a byte[] returns a base 64 representation
	 * 
	 * @param data
	 *            byte[]
	 * @return String
	 */
	protected String byteToBase64(final byte[] data) {
		return Base64.encodeBase64String(data);
	}

	/**
	 * Return SSO token to use in cross site parameters valid for few minutes.
	 * 
	 * @param login
	 *            The login of the user.
	 * @param userKey
	 *            The key of the user.
	 * @return SSO token to use as cross site parameter.
	 */
	private String getSsoToken(final String login, final String userKey) throws Exception {
		// Uses a secure Random not a simple Random
		final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		// Salt generation 64 bits long
		final byte[] bSalt = new byte[8];
		random.nextBytes(bSalt);
		// Digest computation
		final long expire = System.currentTimeMillis()
				+ DateUtils.MILLIS_PER_MINUTE * get("sso.duration", DEFAULT_TIMEOUT);
		final byte[] bDigest = getHash(get("sso.iteration", 1000), login + userKey + expire, bSalt);
		final String sDigest = byteToBase64(bDigest);
		final String sSalt = byteToBase64(bSalt);
		// Secret key of DES algorithm used to generated the SSO token.
		final String ssoKey = configuration.get("sso.secret");
		// Generated an encrypted key, valid for 30 minutes
		return encrypt(
				login + "|"
						+ sDigest + "|" + sSalt + "|" + new String(
								Base64.encodeInteger(new BigInteger(String.valueOf(expire))), StandardCharsets.UTF_8),
				ssoKey);
	}

	/**
	 * Return the key used to compare for a given login. The password (salted or
	 * not) from LDAP, will be hashed to build the final key.
	 */
	private String getUserKey(final String login) {
		return iamProvider.getConfiguration().getUserRepository().getToken(login);
	}

	@Override
	public String getKey() {
		return "feature:sso:salt";
	}
}