package io.statnett.k3a.authz.ldap;

public final class LdapGroupAclAuthorizerIntegrationIT
extends AbstractLdapAuthenticateCallbackHandlerIntegrationIT {

    @Override
    protected String getAuthorizerClassName() {
        return LdapGroupAclAuthorizer.class.getName();
    }

    @Override
    protected boolean isKraftMode() {
        return false;
    }

}
