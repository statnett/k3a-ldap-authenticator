package io.statnett.k3a.authz.ldap;

import io.statnett.k3a.authz.ldap.utils.LdapConnectionSpec;
import org.zapodot.junit.ldap.EmbeddedLdapRule;
import org.zapodot.junit.ldap.EmbeddedLdapRuleBuilder;

final class EmbeddedLdapUtils {

    private static final boolean USE_LDAPS = false;
    static final String LDAP_BASE_DN = "dc=example,dc=com";
    static final String LDAP_ADMIN_DN = "cn=admin," + LDAP_BASE_DN;
    static final char[] LDAP_ADMIN_PASSWORD = "admin".toCharArray();
    static final String EXISTING_USERNAME = "testuser";
    static final String EXISTING_RDN = "cn=" + EXISTING_USERNAME + ",ou=People";
    static final char[] EXISTING_USER_PASSWORD = "secret".toCharArray();
    static final String USERNAME_TO_DN_FORMAT = "cn=%s,ou=People," + LDAP_BASE_DN;
    static final String USERNAME_TO_UNIQUE_SEARCH_FORMAT = "uid=%s";

    private EmbeddedLdapUtils() {
    }

    static EmbeddedLdapRule createEmbeddedLdapRule() {
        return EmbeddedLdapRuleBuilder.newInstance().usingDomainDsn(LDAP_BASE_DN).importingLdifs("ldap/zapodot-bootstrap.ldif").build();
    }

    static LdapConnectionSpec getLdapConnectionSpec(final EmbeddedLdapRule ldapRule) {
        return new LdapConnectionSpec("localhost", ldapRule.embeddedServerPort(), USE_LDAPS, LDAP_BASE_DN);
    }

}
