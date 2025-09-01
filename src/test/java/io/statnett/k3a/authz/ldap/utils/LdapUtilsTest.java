package io.statnett.k3a.authz.ldap.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public final class LdapUtilsTest {

    @Test
    public void testEscape1() {
        Assertions.assertEquals("foo", LdapUtils.escape("foo"));
    }

    @Test
    public void testEscape2() {
        Assertions.assertEquals("\\#foo", LdapUtils.escape("#foo"));
    }

    @Test
    public void testEscape3() {
        Assertions.assertEquals("\\ foo\\ ", LdapUtils.escape(" foo "));
    }

    @Test
    public void testEscape4() {
        Assertions.assertEquals("foo#", LdapUtils.escape("foo#"));
    }

    @Test
    public void testEscape5() {
        Assertions.assertEquals("f\\, oo", LdapUtils.escape("f, oo"));
    }

    @Test
    public void testEscape6() {
        Assertions.assertEquals("foo\\+\\\"\\<\\>\\;", LdapUtils.escape("foo+\"<>;"));
    }

    @Disabled("As of 2007-04-24, no longer escaping high control characters.")
    @Test
    public void xtestEscape7() {
        Assertions.assertEquals("foo\\7f", LdapUtils.escape("foo\u007f"));
    }

    @Disabled("As of 2007-04-24, no longer escaping high control characters.")
    @Test
    public void xtestEscape8() {
        Assertions.assertEquals("foo\\c4\\8d", LdapUtils.escape("foo\uc48d"));
    }

}
