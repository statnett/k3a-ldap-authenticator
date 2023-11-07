package io.statnett.k3a.authz.ldap.utils;

public interface UsernamePasswordAuthenticator {

    boolean authenticate(String username, char[] password);

}
