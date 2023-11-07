package no.shhsoft.utils;

/**
 * NOTE: Heavily trimmed version of Sverre's original utility.
 *
 * @author <a href="mailto:shh@thathost.com">Sverre H. Huseby</a>
 */
public final class StringUtils {

    public static boolean isBlank(final String s) {
        return s == null || s.trim().length() == 0;
    }

}
