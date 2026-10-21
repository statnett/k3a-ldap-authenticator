package io.statnett.k3a.authz.ldap.utils;

import javax.naming.ldap.LdapContext;

public interface LdapContextProvider {

    LdapContext getContext();

    void discardContext();

}
