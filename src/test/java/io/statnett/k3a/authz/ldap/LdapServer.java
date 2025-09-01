package io.statnett.k3a.authz.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.LDAPException;
import io.statnett.k3a.authz.ldap.utils.LdapConnectionSpec;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Paths;

public final class LdapServer {

    public static final String LDAP_BASE_DN = "dc=example,dc=com";
    public static final String LDAP_ADMIN_DN = "cn=admin," + LDAP_BASE_DN;
    public static final String LDAP_ADMIN_PASSWORD = "admin";
    public static final String EXISTING_USERNAME = "testuser";
    public static final String EXISTING_RDN = "cn=" + EXISTING_USERNAME + ",ou=People";
    public static final char[] EXISTING_USER_PASSWORD = "secret".toCharArray();
    public static final String PRODUCER_WITH_USER_ALLOW_USER_PASS = "producer1";
    public static final String PRODUCER_WITH_GROUP_ALLOW_USER_PASS = "producer2";
    public static final String PRODUCER_WITH_GROUP_DENY_USER_PASS = "producer3";
    public static final String PRODUCERS_GROUP = "cn=producers,ou=Groups," + LDAP_BASE_DN;
    public static final String DENIED_PRODUCERS_GROUP = "cn=deniedproducers,ou=Groups," + LDAP_BASE_DN;
    public static final String NON_PRODUCER_USER_PASS = "nonproducer";
    public static final String USERNAME_TO_DN_FORMAT = "cn=%s,ou=People," + LDAP_BASE_DN;
    public static final String USERNAME_TO_UNIQUE_SEARCH_FORMAT = "uid=%s";
    private InMemoryDirectoryServer ldap;
    private final String ldifResource;

    public LdapServer(final String ldifResource) {
        this.ldifResource = ldifResource;
    }

    public void start() {
        try {
            final InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE_DN);
            config.addAdditionalBindCredentials(LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD);
            config.setSchema(null);
            ldap = new InMemoryDirectoryServer(config);
            ldap.importFromLDIF(true, resourceToFile(ldifResource));
            ldap.startListening();
        } catch (final LDAPException e) {
            throw new RuntimeException(e);
        }
    }

    private static File resourceToFile(final String resource) {
        try {
            return Paths.get(LdapServer.class.getResource(resource).toURI()).toFile();
        } catch (final URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public void stop() {
        ldap.shutDown(true);
    }

    public String getLdapBaseDn() {
        return LDAP_BASE_DN;
    }

    public String getLdapHost() {
        return "127.0.0.1";
    }

    public int getLdapPort() {
        return ldap.getListenPort();
    }

    public LdapConnectionSpec getLdapConnectionSpec() {
        return new LdapConnectionSpec(getLdapHost(), getLdapPort(), false, getLdapBaseDn());
    }

    public static void main(final String[] args)
    throws InterruptedException {
        final LdapServer server = new LdapServer("/ldap/unboundid-bootstrap.ldif");
        server.start();
        System.out.println("port: " + server.getLdapPort());
        Thread.sleep(60000L);
        server.stop();
    }

}
