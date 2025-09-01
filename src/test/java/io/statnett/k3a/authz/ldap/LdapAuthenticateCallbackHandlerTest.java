package io.statnett.k3a.authz.ldap;

import io.statnett.k3a.authz.ldap.utils.UsernamePasswordAuthenticator;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public final class LdapAuthenticateCallbackHandlerTest {

    private static final String KNOWN_USERNAME = "user";
    private static final char[] KNOWN_PASSWORD = "password".toCharArray();
    private static final UsernamePasswordAuthenticator KNOWN_USERNAME_PASSWORD_AUTHENTICATOR = new AcceptOneUsernamePasswordAuthenticator();

    private static final class AcceptOneUsernamePasswordAuthenticator
    implements UsernamePasswordAuthenticator {

        @Override
        public boolean authenticate(final String username, final char[] password) {
            return KNOWN_USERNAME.equals(username) && Arrays.equals(KNOWN_PASSWORD, password);
        }

    }

    @Test
    public void shouldAcceptOkConfig() {
        kafkaDestroyCallbackHandler(kafkaCreateCallbackHandler());
    }

    @Test
    public void shouldNotAcceptWrongSaslMechanism() {
        final IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> kafkaCreateCallbackHandler(getWorkingConfigs(), "wrong"));
        Assertions.assertTrue(exception.getMessage().contains("SASL mechanism \"PLAIN\""));
    }

    @Test
    public void shouldNotAcceptMissingConfig() {
        final Map<String, Object> workingConfigs = getWorkingConfigs();
        if (!(workingConfigs instanceof LinkedHashMap)) {
            throw new RuntimeException("The test map must be ordered.");
        }
        for (int q = 0; q < workingConfigs.size(); q++) {
            final Map<String, Object> nonWorkingConfigs = new HashMap<>();
            int idx = 0;
            String expectedErrorSubstring = null;
            for (final Map.Entry<String, Object> entry : workingConfigs.entrySet()) {
                if (idx++ == q) {
                    expectedErrorSubstring = entry.getKey();
                    continue;
                }
                nonWorkingConfigs.put(entry.getKey(), entry.getValue());
            }
            final IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> kafkaCreateCallbackHandler(nonWorkingConfigs));
            Assertions.assertTrue(exception.getMessage().contains(expectedErrorSubstring));
        }
    }

    @Test
    public void shouldNotAcceptInvalidPortNumber() {
        final Map<String, Object> configs = getWorkingConfigs();
        configs.put("authz.ldap.port", "foo");
        final IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> kafkaCreateCallbackHandler(configs));
        Assertions.assertTrue(exception.getMessage().contains("must be numeric"));
    }

    @Test
    public void shouldNotAcceptMissingUsernameCallback() {
        final LdapAuthenticateCallbackHandler callbackHandler = kafkaCreateCallbackHandler();
        final IllegalStateException exception = Assertions.assertThrows(IllegalStateException.class, () -> callbackHandler.handle(new Callback[]{getPasswordCallback(KNOWN_PASSWORD)}));
        Assertions.assertTrue(exception.getMessage().contains("NameCallback"));
        kafkaDestroyCallbackHandler(callbackHandler);
    }

    @Test
    public void shouldNotAcceptMissingPasswordCallback() {
        final LdapAuthenticateCallbackHandler callbackHandler = kafkaCreateCallbackHandler();
        final IllegalStateException exception = Assertions.assertThrows(IllegalStateException.class, () -> callbackHandler.handle(new Callback[]{getUsernameCallback(KNOWN_USERNAME)}));
        Assertions.assertTrue(exception.getMessage().contains("PlainAuthenticationCallback"));
        kafkaDestroyCallbackHandler(callbackHandler);
    }

    @Test
    public void shouldNotAcceptUnhandledCallback() {
        final LdapAuthenticateCallbackHandler callbackHandler = kafkaCreateCallbackHandler();
        try {
            callbackHandler.handle(new Callback[] { new TextInputCallback("foo") });
            Assertions.fail("Did not get expected exception.");
        } catch (final UnsupportedCallbackException e) {
            Assertions.assertInstanceOf(TextInputCallback.class, e.getCallback(), "Did not get expected exception.");
        }
        kafkaDestroyCallbackHandler(callbackHandler);
    }

    @Test
    public void shouldAcceptKnownUserNoMatterTheCallbackOrder() {
        final LdapAuthenticateCallbackHandler callbackHandler = kafkaCreateCallbackHandler();
        try {
            final PlainAuthenticateCallback passwordCallback1 = getPasswordCallback(KNOWN_PASSWORD);
            callbackHandler.handle(new Callback[] { getUsernameCallback(KNOWN_USERNAME), passwordCallback1 });
            Assertions.assertTrue(passwordCallback1.authenticated());

            final PlainAuthenticateCallback passwordCallback2 = getPasswordCallback(KNOWN_PASSWORD);
            callbackHandler.handle(new Callback[] { passwordCallback2, getUsernameCallback(KNOWN_USERNAME) });
            Assertions.assertTrue(passwordCallback2.authenticated());
        } catch (final UnsupportedCallbackException e) {
            throw new RuntimeException("Got unexpected exception.", e);
        }
        kafkaDestroyCallbackHandler(callbackHandler);
    }

    @Test
    public void shouldNotAcceptWrongUsername() {
        final LdapAuthenticateCallbackHandler callbackHandler = kafkaCreateCallbackHandler();
        try {
            final PlainAuthenticateCallback passwordCallback = getPasswordCallback(KNOWN_PASSWORD);
            callbackHandler.handle(new Callback[] { getUsernameCallback("wrong"), passwordCallback });
            Assertions.assertFalse(passwordCallback.authenticated());
        } catch (final UnsupportedCallbackException e) {
            throw new RuntimeException("Got unexpected exception.", e);
        }
        kafkaDestroyCallbackHandler(callbackHandler);
    }

    @Test
    public void shouldNotAcceptWrongPassword() {
        final LdapAuthenticateCallbackHandler callbackHandler = kafkaCreateCallbackHandler();
        try {
            final PlainAuthenticateCallback passwordCallback = getPasswordCallback("wrong".toCharArray());
            callbackHandler.handle(new Callback[] { getUsernameCallback(KNOWN_USERNAME), passwordCallback });
            Assertions.assertFalse(passwordCallback.authenticated());
        } catch (final UnsupportedCallbackException e) {
            throw new RuntimeException("Got unexpected exception.", e);
        }
        kafkaDestroyCallbackHandler(callbackHandler);
    }

    private Callback getUsernameCallback(final String username) {
        return new NameCallback("prompt", username);
    }

    private PlainAuthenticateCallback getPasswordCallback(final char[] password) {
        return new PlainAuthenticateCallback(password);
    }

    private LdapAuthenticateCallbackHandler kafkaCreateCallbackHandler() {
        return kafkaCreateCallbackHandler(getWorkingConfigs());
    }

    private LdapAuthenticateCallbackHandler kafkaCreateCallbackHandler(final Map<String, Object> configs) {
        return kafkaCreateCallbackHandler(configs, "PLAIN");
    }

    private LdapAuthenticateCallbackHandler kafkaCreateCallbackHandler(final Map<String, Object> configs, final String saslMechanism) {
        final LdapAuthenticateCallbackHandler callbackHandler = new LdapAuthenticateCallbackHandler((spec, usernameToDnFormat, usernameToUniqueSearchFormat, userDn, userPassword) -> LdapAuthenticateCallbackHandlerTest.KNOWN_USERNAME_PASSWORD_AUTHENTICATOR);
        callbackHandler.close();
        callbackHandler.configure(configs, saslMechanism, Collections.emptyList());
        return callbackHandler;
    }

    private void kafkaDestroyCallbackHandler(final LdapAuthenticateCallbackHandler callbackHandler) {
        callbackHandler.close();
    }

    private Map<String, Object> getWorkingConfigs() {
        final Map<String, Object> map = new LinkedHashMap<>();
        map.put("authz.ldap.host", "localhost");
        map.put("authz.ldap.port", 389);
        map.put("authz.ldap.base.dn", "dc=example,dc=com");
        map.put("authz.ldap.username.to.dn.format", "%s");
        return map;
    }

}
