package io.statnett.k3a.authz.ldap;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        assertTrue(authenticator.authenticateByDn(LdapServer.LDAP_ADMIN_DN, LdapServer.LDAP_ADMIN_PASSWORD.toCharArray()));
        assertTrue(authenticator.authenticateByDn(LdapServer.EXISTING_RDN + "," + LdapServer.LDAP_BASE_DN, LdapServer.EXISTING_USER_PASSWORD));
    }

    @Test
    public void shouldAcceptValidUsernameAndPassword() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        assertTrue(authenticator.authenticate(LdapServer.EXISTING_USERNAME, LdapServer.EXISTING_USER_PASSWORD));
    }

    @Test
    public void shouldPopulateGroups() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        assertTrue(authenticator.authenticate(LdapServer.EXISTING_USERNAME, LdapServer.EXISTING_USER_PASSWORD));
        final Set<String> groups = UserToGroupsCache.getInstance().getGroupsForUser(LdapServer.EXISTING_USERNAME);
        assertNotNull(groups);
        assertEquals(1, groups.size());
    }

    @Test
    public void shouldPopulateGroupsUsingServiceAccount() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticatorWithServiceUser();
        assertTrue(authenticator.authenticate(LdapServer.EXISTING_USERNAME, LdapServer.EXISTING_USER_PASSWORD));
        final Set<String> groups = UserToGroupsCache.getInstance().getGroupsForUser(LdapServer.EXISTING_USERNAME);
        assertNotNull(groups);
        assertEquals(1, groups.size());
    }
    @Test
    public void shouldDenyEmptyUserDnOrPassword() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        assertFalse(authenticator.authenticateByDn(LdapServer.LDAP_ADMIN_DN, null));
        assertFalse(authenticator.authenticateByDn(LdapServer.LDAP_ADMIN_DN, "".toCharArray()));
        assertFalse(authenticator.authenticateByDn(null, LdapServer.LDAP_ADMIN_PASSWORD.toCharArray()));
        assertFalse(authenticator.authenticateByDn("", LdapServer.LDAP_ADMIN_PASSWORD.toCharArray()));
        assertFalse(authenticator.authenticateByDn(null, null));
        assertFalse(authenticator.authenticateByDn("", "".toCharArray()));
    }

    private LdapUsernamePasswordAuthenticator getAuthenticator() {
        return new LdapUsernamePasswordAuthenticator(ldapServer.getLdapConnectionSpec(), LdapServer.USERNAME_TO_DN_FORMAT, LdapServer.USERNAME_TO_UNIQUE_SEARCH_FORMAT, null, null);
    }

    private LdapUsernamePasswordAuthenticator getAuthenticatorWithServiceUser() {
        return new LdapUsernamePasswordAuthenticator(ldapServer.getLdapConnectionSpec(), LdapServer.USERNAME_TO_DN_FORMAT, LdapServer.USERNAME_TO_UNIQUE_SEARCH_FORMAT, LdapServer.LDAP_ADMIN_DN, new String(LdapServer.LDAP_ADMIN_PASSWORD.toCharArray()));
    }

}
