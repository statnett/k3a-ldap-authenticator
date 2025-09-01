package io.statnett.k3a.authz.ldap;

import io.statnett.k3a.authz.ldap.utils.time.TestTimeProvider;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public final class UserToGroupsCacheTest {

    private final TestTimeProvider timeProvider = new TestTimeProvider();
    private final Set<String> groupSet1 = new HashSet<>();
    private final Set<String> groupSet2 = new HashSet<>();

    public UserToGroupsCacheTest() {
        groupSet1.add("group1");
        groupSet1.add("group2");
        groupSet2.add("groupA");
        groupSet2.add("groupB");
    }

    @Test
    public void shouldReturnFetched() {
        final UserToGroupsCache cache = new UserToGroupsCache(timeProvider);
        cache.fetchGroupsForUserIfNeeded("foo", s -> groupSet1);
        assertEquals(groupSet1, cache.getGroupsForUser("foo"));
    }

    @Test
    public void shouldReturnNullAfterExpiry() {
        final UserToGroupsCache cache = new UserToGroupsCache(timeProvider);
        cache.setGroupsForUser("foo", groupSet1);
        timeProvider.add(UserToGroupsCache.TTL);
        assertNull(cache.getGroupsForUser("foo"));
    }

    @Test
    public void shouldNotFetchNewBeforeNearExpiry() {
        final UserToGroupsCache cache = new UserToGroupsCache(timeProvider);
        cache.setGroupsForUser("foo", groupSet1);
        cache.fetchGroupsForUserIfNeeded("foo", s -> groupSet2);
        assertEquals(groupSet1, cache.getGroupsForUser("foo"));
    }

    @Test
    public void shouldReturnNewlyFetchedNearExpiry() {
        final UserToGroupsCache cache = new UserToGroupsCache(timeProvider);
        cache.setGroupsForUser("foo", groupSet1);
        timeProvider.add(UserToGroupsCache.TTL - UserToGroupsCache.REFRESH_WHEN_LESS_THAN_MS + 1);
        cache.fetchGroupsForUserIfNeeded("foo", s -> groupSet2);
        assertEquals(groupSet2, cache.getGroupsForUser("foo"));
    }

}
