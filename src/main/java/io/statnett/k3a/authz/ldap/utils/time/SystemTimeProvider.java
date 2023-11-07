package io.statnett.k3a.authz.ldap.utils.time;

public final class SystemTimeProvider
implements TimeProvider {

    private static final SystemTimeProvider INSTANCE = new SystemTimeProvider();

    public static SystemTimeProvider getInstance() {
        return INSTANCE;
    }

    @Override
    public long currentTimeMillis() {
        return System.currentTimeMillis();
    }

}
