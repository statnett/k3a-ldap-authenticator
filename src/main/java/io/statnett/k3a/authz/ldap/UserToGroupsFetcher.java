package io.statnett.k3a.authz.ldap;

import java.util.Set;

interface UserToGroupsFetcher {

    Set<String> fetchGroups(String username);

}
