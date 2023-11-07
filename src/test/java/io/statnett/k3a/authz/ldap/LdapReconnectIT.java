package io.statnett.k3a.authz.ldap;

import no.shhsoft.ldap.LdapConnectionSpec;
import no.shhsoft.security.UsernamePasswordAuthenticator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public final class LdapReconnectIT {

    @Test
    public void shouldReconnectAfterConnectionLoss() {
        final LdapServer ldap = new LdapServer();
        ldap.start();
        final UserToGroupsCache groupsCache = UserToGroupsCache.getInstance();
        groupsCache.clear();
        final LdapConnectionSpec spec = new LdapConnectionSpec(ldap.getLdapHost(), ldap.getLdapPort(), false, ldap.getLdapBaseDn());
        final UsernamePasswordAuthenticator authenticator = new LdapUsernamePasswordAuthenticator(spec, LdapServer.USERNAME_TO_DN_FORMAT, LdapServer.USERNAME_TO_UNIQUE_SEARCH_FORMAT, LdapServer.LDAP_ADMIN_DN, LdapServer.LDAP_ADMIN_PASSWORD);
        callAuthenticator(authenticator);
        final int numReconnects = groupsCache.getNumReconnects();
        groupsCache.makeUseless();
        callAuthenticator(authenticator);
        Assertions.assertEquals(groupsCache.getNumReconnects(), numReconnects + 1, "Expected reconnect, but got none.");
    }

    private void callAuthenticator(final UsernamePasswordAuthenticator authenticator) {
        Assertions.assertTrue(authenticator.authenticate(LdapServer.PRODUCER_WITH_GROUP_ALLOW_USER_PASS, LdapServer.PRODUCER_WITH_GROUP_ALLOW_USER_PASS.toCharArray()));
        Assertions.assertEquals(1, UserToGroupsCache.getInstance().getGroupsForUser(LdapServer.PRODUCER_WITH_GROUP_ALLOW_USER_PASS).size());
    }

}
