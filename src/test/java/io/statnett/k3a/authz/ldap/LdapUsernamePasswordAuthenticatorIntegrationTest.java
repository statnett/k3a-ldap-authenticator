package io.statnett.k3a.authz.ldap;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

public final class LdapUsernamePasswordAuthenticatorIntegrationTest {

    private static LdapServer ldapServer;

    @BeforeAll
    public static void beforeAll() {
        ldapServer = new LdapServer("/ldap/zapodot-bootstrap.ldif");
        ldapServer.start();
    }

    @AfterAll
    public static void afterAll() {
        ldapServer.stop();
    }

    @Test
    public void shouldAcceptValidUserDnAndPassword() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        Assertions.assertTrue(authenticator.authenticateByDn(LdapServer.LDAP_ADMIN_DN, LdapServer.LDAP_ADMIN_PASSWORD.toCharArray()));
        Assertions.assertTrue(authenticator.authenticateByDn(LdapServer.EXISTING_RDN + "," + LdapServer.LDAP_BASE_DN, LdapServer.EXISTING_USER_PASSWORD));
    }

    @Test
    public void shouldAcceptValidUsernameAndPassword() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        Assertions.assertTrue(authenticator.authenticate(LdapServer.EXISTING_USERNAME, LdapServer.EXISTING_USER_PASSWORD));
    }

    @Test
    public void shouldPopulateGroups() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        Assertions.assertTrue(authenticator.authenticate(LdapServer.EXISTING_USERNAME, LdapServer.EXISTING_USER_PASSWORD));
        final Set<String> groups = UserToGroupsCache.getInstance().getGroupsForUser(LdapServer.EXISTING_USERNAME);
        Assertions.assertNotNull(groups);
        Assertions.assertEquals(1, groups.size());
    }

    @Test
    public void shouldPopulateGroupsUsingServiceAccount() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticatorWithServiceUser();
        Assertions.assertTrue(authenticator.authenticate(LdapServer.EXISTING_USERNAME, LdapServer.EXISTING_USER_PASSWORD));
        final Set<String> groups = UserToGroupsCache.getInstance().getGroupsForUser(LdapServer.EXISTING_USERNAME);
        Assertions.assertNotNull(groups);
        Assertions.assertEquals(1, groups.size());
    }
    @Test
    public void shouldDenyEmptyUserDnOrPassword() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        Assertions.assertFalse(authenticator.authenticateByDn(LdapServer.LDAP_ADMIN_DN, null));
        Assertions.assertFalse(authenticator.authenticateByDn(LdapServer.LDAP_ADMIN_DN, "".toCharArray()));
        Assertions.assertFalse(authenticator.authenticateByDn(null, LdapServer.LDAP_ADMIN_PASSWORD.toCharArray()));
        Assertions.assertFalse(authenticator.authenticateByDn("", LdapServer.LDAP_ADMIN_PASSWORD.toCharArray()));
        Assertions.assertFalse(authenticator.authenticateByDn(null, null));
        Assertions.assertFalse(authenticator.authenticateByDn("", "".toCharArray()));
    }

    private LdapUsernamePasswordAuthenticator getAuthenticator() {
        return new LdapUsernamePasswordAuthenticator(ldapServer.getLdapConnectionSpec(), LdapServer.USERNAME_TO_DN_FORMAT, LdapServer.USERNAME_TO_UNIQUE_SEARCH_FORMAT, null, null);
    }

    private LdapUsernamePasswordAuthenticator getAuthenticatorWithServiceUser() {
        return new LdapUsernamePasswordAuthenticator(ldapServer.getLdapConnectionSpec(), LdapServer.USERNAME_TO_DN_FORMAT, LdapServer.USERNAME_TO_UNIQUE_SEARCH_FORMAT, LdapServer.LDAP_ADMIN_DN, new String(LdapServer.LDAP_ADMIN_PASSWORD.toCharArray()));
    }

}
