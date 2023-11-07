package no.shhsoft.security;

/**
 * @author <a href="mailto:shh@thathost.com">Sverre H. Huseby</a>
 */
public interface UsernamePasswordAuthenticator {

    boolean authenticate(String username, char[] password);

}
