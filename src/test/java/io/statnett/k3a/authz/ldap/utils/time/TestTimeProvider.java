package io.statnett.k3a.authz.ldap.utils.time;

import io.statnett.k3a.authz.ldap.utils.time.TimeProvider;

public final class TestTimeProvider
implements TimeProvider {

    private long ctm;

    @Override
    public long currentTimeMillis() {
        return ctm;
    }

    public void set(final long ctm) {
        this.ctm = ctm;
    }

    public void add(final long diff) {
        ctm += diff;
    }

}
