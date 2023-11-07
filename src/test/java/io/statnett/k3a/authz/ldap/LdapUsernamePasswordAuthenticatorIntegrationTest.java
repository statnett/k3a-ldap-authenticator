package io.statnett.k3a.authz.ldap;

import org.junit.ClassRule;
import org.junit.Test;
import org.zapodot.junit.ldap.EmbeddedLdapRule;

import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public final class LdapUsernamePasswordAuthenticatorIntegrationTest {

    @ClassRule
    public static final EmbeddedLdapRule LDAP_RULE = EmbeddedLdapUtils.createEmbeddedLdapRule();

    @Test
    public void shouldAcceptValidUserDnAndPassword() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        assertTrue(authenticator.authenticateByDn(EmbeddedLdapUtils.LDAP_ADMIN_DN, EmbeddedLdapUtils.LDAP_ADMIN_PASSWORD));
        assertTrue(authenticator.authenticateByDn(EmbeddedLdapUtils.EXISTING_RDN + "," + EmbeddedLdapUtils.LDAP_BASE_DN, EmbeddedLdapUtils.EXISTING_USER_PASSWORD));
    }

    @Test
    public void shouldAcceptValidUsernameAndPassword() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        assertTrue(authenticator.authenticate(EmbeddedLdapUtils.EXISTING_USERNAME, EmbeddedLdapUtils.EXISTING_USER_PASSWORD));
    }

    @Test
    public void shouldPopulateGroups() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        assertTrue(authenticator.authenticate(EmbeddedLdapUtils.EXISTING_USERNAME, EmbeddedLdapUtils.EXISTING_USER_PASSWORD));
        final Set<String> groups = UserToGroupsCache.getInstance().getGroupsForUser(EmbeddedLdapUtils.EXISTING_USERNAME);
        assertNotNull(groups);
        assertEquals(1, groups.size());
    }

    @Test
    public void shouldPopulateGroupsUsingServiceAccount() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticatorWithServiceUser();
        assertTrue(authenticator.authenticate(EmbeddedLdapUtils.EXISTING_USERNAME, EmbeddedLdapUtils.EXISTING_USER_PASSWORD));
        final Set<String> groups = UserToGroupsCache.getInstance().getGroupsForUser(EmbeddedLdapUtils.EXISTING_USERNAME);
        assertNotNull(groups);
        assertEquals(1, groups.size());
    }
    @Test
    public void shouldDenyEmptyUserDnOrPassword() {
        final LdapUsernamePasswordAuthenticator authenticator = getAuthenticator();
        assertFalse(authenticator.authenticateByDn(EmbeddedLdapUtils.LDAP_ADMIN_DN, null));
        assertFalse(authenticator.authenticateByDn(EmbeddedLdapUtils.LDAP_ADMIN_DN, "".toCharArray()));
        assertFalse(authenticator.authenticateByDn(null, EmbeddedLdapUtils.LDAP_ADMIN_PASSWORD));
        assertFalse(authenticator.authenticateByDn("", EmbeddedLdapUtils.LDAP_ADMIN_PASSWORD));
        assertFalse(authenticator.authenticateByDn(null, null));
        assertFalse(authenticator.authenticateByDn("", "".toCharArray()));
    }

    private LdapUsernamePasswordAuthenticator getAuthenticator() {
        return new LdapUsernamePasswordAuthenticator(EmbeddedLdapUtils.getLdapConnectionSpec(LDAP_RULE), EmbeddedLdapUtils.USERNAME_TO_DN_FORMAT, EmbeddedLdapUtils.USERNAME_TO_UNIQUE_SEARCH_FORMAT, null, null);
    }

    private LdapUsernamePasswordAuthenticator getAuthenticatorWithServiceUser() {
        return new LdapUsernamePasswordAuthenticator(EmbeddedLdapUtils.getLdapConnectionSpec(LDAP_RULE), EmbeddedLdapUtils.USERNAME_TO_DN_FORMAT, EmbeddedLdapUtils.USERNAME_TO_UNIQUE_SEARCH_FORMAT, EmbeddedLdapUtils.LDAP_ADMIN_DN, new String(EmbeddedLdapUtils.LDAP_ADMIN_PASSWORD));
    }

}
