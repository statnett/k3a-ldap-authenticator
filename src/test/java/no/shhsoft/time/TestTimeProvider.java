package no.shhsoft.time;

/**
 * @author <a href="mailto:shh@thathost.com">Sverre H. Huseby</a>
 */
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
