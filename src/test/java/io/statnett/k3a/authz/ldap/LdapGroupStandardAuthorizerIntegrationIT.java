package io.statnett.k3a.authz.ldap;

public final class LdapGroupStandardAuthorizerIntegrationIT
extends AbstractLdapAuthenticateCallbackHandlerIntegrationIT {

    @Override
    protected String getAuthorizerClassName() {
        return LdapGroupStandardAuthorizer.class.getName();
    }

    @Override
    protected boolean isKraftMode() {
        return true;
    }

}
