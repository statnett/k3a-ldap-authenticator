package no.shhsoft.time;

/**
 * @author <a href="mailto:shh@thathost.com">Sverre H. Huseby</a>
 */
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
