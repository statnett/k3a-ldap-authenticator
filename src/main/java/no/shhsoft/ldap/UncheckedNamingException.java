package no.shhsoft.ldap;

/**
 * @author <a href="mailto:shh@thathost.com">Sverre H. Huseby</a>
 */
public final class UncheckedNamingException
extends RuntimeException {

    public UncheckedNamingException(final Throwable throwable) {
        super(throwable);
    }

}
