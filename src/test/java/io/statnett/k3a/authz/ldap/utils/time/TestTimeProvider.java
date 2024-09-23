package io.statnett.k3a.authz.ldap.utils.time;

public final class TestTimeProvider
implements TimeProvider {

    private long ctm;

    @Override
    public long currentTimeMillis() {
        return ctm;
    }

    public void add(final long diff) {
        ctm += diff;
    }

}
