# k3a-ldap-authenticator

This module contains:

* A [Kafka
  `AuthenticateCallbackHandler`](src/main/java/io/statnett/k3a/authz/ldap/LdapAuthenticateCallbackHandler.java)
  that uses a directory (LDAP/Active Directory) to verify a username
  and a plain-text password.
* A [Kafka
  `AclAuthorizer`](src/main/java/io/statnett/k3a/authz/ldap/LdapGroupAclAuthorizer.java)
  and
  [StandardAuthorizer](src/main/java/io/statnett/k3a/authz/ldap/LdapGroupStandardAuthorizer.java)
  that know about principals of type `Group`, and check them against
  LDAP/Active Directory group membership. The first is for
  installations that use ZooKeeper ACLs, the second for installations
  running without ZooKeepers.

If you do not care about group membership, you only need to set up the
first class. For group membership you need both, since the
`AclAuthorizer`/`StandardAuthorizer` builds on data fetched by the
`AuthenticateCallbackHandler`.

## Misc. notes

* Since all this is based on plain-text passwords, you will want to
  run it over SSL/TLS.
* This is SASL_PLAIN, meaning that both the Kafka broker and the
  client application will get access to the user's password before
  passing it on to the directory server where the authentication is
  taking place. In many environments this is considered unacceptable:
  Look for something like OAUTH or SAML instead.
* Although group membership is cached, there is no caching of the
  authentication result, but it is trivial to implement if needed. If
  you do, please do not use the plain-text password as part of the
  cache key, but pass it through a hashing function first.

## Configuration
  
Configuration is done using Kafka properties: Either
`dot.separated.properties`, or `KAFKA_ENVIRONMENT_VARIABLES`. To use
environment variables, capitalize every letter of the original
property, replace any underscores with a double underscore, replace
dots with underscores, and prefix with `KAFKA_`.

### Kafka integration

The `.jar`-file of this project must be made available on the Kafka
Broker classpath, typically in `/usr/share/java/kafka/`.

### Authenticator configuration

You will need a binding and a listener for either `SASL_SSL` or
`SASL_PLAINTEXT`. In the following we assume `SASL_SSL`, and a binding
named `HUMAN`:

```properties
advertised.listeners=... ,HUMAN://broker:9094
listener.security.protocol.map=... ,HUMAN:SASL_SSL
```

Tell Kafka to enable SASL, and to use our class to handle the protocol
binding created above:

```properties
listener.name.human.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required ;
listener.name.human.plain.sasl.server.callback.handler.class=io.statnett.k3a.authz.ldap.LdapAuthenticateCallbackHandler
sasl.enabled.mechanisms=PLAIN
```

The authenticator plug-in expects some configuration parameters,
prefixed with `authz.ldap`, to tell it how to connect to and handle
the LDAP Directory:

```properties
authz.ldap.host=openldap
authz.ldap.port=389
authz.ldap.base.dn=dc=example,dc=com
authz.ldap.username.to.dn.format=cn=%s,ou=People,dc=example,dc=com
```

LDAPS (TLS) is assumed if the port is 636. For all other ports,
plain-text LDAP is assumed. If using LDAPS with a self-signed
certificate, the Broker JVM must be told to trust your
certificates. How to do that is beyond the scope of this README.

The final parameter, `ldap.username.to.dn.format`, specifies how the
incoming username should be transformed to match whatever the
directory expects as part of a bind operation. The `%s` combination
will be replaced by a properly escaped version of what the user
provided. On Active Directory this string should often be specified as
just `%s`, since the directory authenticates using just the username
without matching a full DN.

### Group authorizer configuration

If you want to enable ACLs which contain a `Group` principal type, you
will need the above configuration, plus our `LdapGroupAclAuthorizer`
(for ZooKeeper ACLs) or `LdapGroupStandardAuthorizer` for KRaft mode
ACLs.

Requirements for our group authorizer:

* Authorization is done based on the automatically populated
  `memberOf` attribute that was introduced in draft [RFC
  2307bis](https://tools.ietf.org/id/draft-howard-rfc2307bis-01.txt).
  Although a draft RFC, this was adopted by Microsoft in Active
  Directory. Later, the same functionality has become available in
  other directories as well.
* The Group authorizer does not use a distinct user for LDAP searches,
  but instead assumes that every user is allowed to search the entire
  LDAP tree to find itself. This is not the case everywhere.

Tell Kafka to use this authorizer like this:

```properties
authorizer.class.name=io.statnett.k3a.authz.ldap.LdapGroupAclAuthorizer
```

or this:

```properties
authorizer.class.name=io.statnett.k3a.authz.ldap.LdapGroupStandardAuthorizer
```

The authorizer will perform a search in the entire LDAP tree to find
the attributes of the authenticated user. The following attribute
tells it how to map a username to a search filter:

```properties
authz.ldap.username.to.unique.search.format=uid=%s
```

Group principals, for use in ACLs, must contain the full DN of the
group:

```text
Group:cn=producers,ou=Groups,dc=example,dc=com
```
