package io.statnett.k3a.authz.ldap;

import no.shhsoft.k3aembedded.K3aEmbedded;
import no.shhsoft.k3aembedded.K3aTestUtils;
import io.statnett.k3a.authz.ldap.utils.LdapConnectionSpec;
import io.statnett.k3a.authz.ldap.utils.UsernamePasswordAuthenticator;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.acl.AccessControlEntry;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.acl.AclPermissionType;
import org.apache.kafka.common.errors.TopicAuthorizationException;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractLdapAuthenticateCallbackHandlerIntegrationIT {

    private static final String TOPIC_WITH_USER_ALLOW = "topic_with_user_principal";
    private static final String TOPIC_WITH_GROUP_ALLOW = "topic_with_group_principal";
    private static final String JAAS_ADMIN_USER_LINE = "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"kafka\" password=\"kafka\" user_kafka=\"kafka\";";
    private static final String ANY_HOST = "*";
    private static LdapServer ldapServer;
    private static K3aEmbedded kafka;

    protected abstract String getAuthorizerClassName();

    protected abstract boolean isKraftMode();

    @BeforeAll
    public final void beforeClass() {
        ldapServer = new LdapServer();
        ldapServer.start();

        final Map<String, Object> map = new HashMap<>();
        map.put("listener.name.sasl_plaintext.sasl.enabled.mechanisms", "PLAIN");
        map.put("listener.name.sasl_plaintext.plain.sasl.jaas.config", JAAS_ADMIN_USER_LINE);
        map.put("listener.name.broker.plain.sasl.jaas.config", JAAS_ADMIN_USER_LINE);
        map.put("listener.name.controller.plain.sasl.jaas.config", JAAS_ADMIN_USER_LINE);
        map.put("sasl.mechanism.inter.broker.protocol", "PLAIN");
        map.put("sasl.mechanism.controller.protocol", "PLAIN");
        map.put("sasl.enabled.mechanisms", "PLAIN");
        map.put("super.users", "User:kafka");
        map.put("listener.security.protocol.map", "BROKER:SASL_PLAINTEXT, CONTROLLER:SASL_PLAINTEXT, SASL_PLAINTEXT:SASL_PLAINTEXT");
        map.put("authorizer.class.name", getAuthorizerClassName());
        map.put("authz.ldap.base.dn", ldapServer.getLdapBaseDn());
        map.put("authz.ldap.host", ldapServer.getLdapHost());
        map.put("authz.ldap.port", ldapServer.getLdapPort());
        map.put("authz.ldap.user.dn", LdapServer.LDAP_ADMIN_DN);
        map.put("authz.ldap.user.passwrd", LdapServer.LDAP_ADMIN_PASSWORD);
        map.put("authz.ldap.username.to.dn.format", LdapServer.USERNAME_TO_DN_FORMAT);
        map.put("authz.ldap.username.to.unique.search.format", LdapServer.USERNAME_TO_UNIQUE_SEARCH_FORMAT);
        map.put("listener.name.sasl_plaintext.plain.sasl.server.callback.handler.class", LdapAuthenticateCallbackHandler.class.getName());
        kafka = new K3aEmbedded.Builder()
                .kraftMode(isKraftMode())
                .additionalPorts(1)
                .additionalConfiguration(map)
                .additionalListenerWithPortIndex("SASL_PLAINTEXT", "SASL_PLAINTEXT", 0)
                .build();
        kafka.start();

        setupTestTopicsAndAcls();
    }

    @AfterAll
    public void afterClass() {
        kafka.stop();
        ldapServer.stop();
    }

    @BeforeEach
    public final void before() {
        UserToGroupsCache.getInstance().clear();
    }

    private void setupTestTopicsAndAcls() {
        assertLdapAuthenticationWorks();
        addTopic(TOPIC_WITH_USER_ALLOW);
        addProducer(TOPIC_WITH_USER_ALLOW, "User:" + LdapServer.PRODUCER_WITH_USER_ALLOW_USER_PASS);
        addTopic(TOPIC_WITH_GROUP_ALLOW);
        addProducer(TOPIC_WITH_GROUP_ALLOW, "Group:" + LdapServer.PRODUCERS_GROUP);
        addDeniedProducer(TOPIC_WITH_GROUP_ALLOW, "Group:" + LdapServer.DENIED_PRODUCERS_GROUP);
    }

    private void assertLdapAuthenticationWorks() {
        final LdapConnectionSpec spec = new LdapConnectionSpec(ldapServer.getLdapHost(), ldapServer.getLdapPort(), false, ldapServer.getLdapBaseDn());
        final UsernamePasswordAuthenticator authenticator = new LdapUsernamePasswordAuthenticator(spec, LdapServer.USERNAME_TO_DN_FORMAT, null, null, null);
        for (final String userPass : Arrays.asList("kafka", LdapServer.PRODUCER_WITH_USER_ALLOW_USER_PASS, LdapServer.PRODUCER_WITH_GROUP_ALLOW_USER_PASS, LdapServer.PRODUCER_WITH_GROUP_DENY_USER_PASS, LdapServer.NON_PRODUCER_USER_PASS)) {
            Assertions.assertTrue(authenticator.authenticate(userPass, userPass.toCharArray()), "Failed for " + userPass);
        }
    }

    @Test
    public final void shouldNotProduceWhenNotProducerByUser() {
        Assertions.assertThrows(TopicAuthorizationException.class, () -> {
            try (final Producer<Integer, String> producer = getProducer(LdapServer.NON_PRODUCER_USER_PASS)) {
                produce(producer, TOPIC_WITH_USER_ALLOW, "foo");
            }
        });
    }

    @Test
    public final void shouldProduceWhenProducerByUser() {
        try (final Producer<Integer, String> producer = getProducer(LdapServer.PRODUCER_WITH_USER_ALLOW_USER_PASS)) {
            produce(producer, TOPIC_WITH_USER_ALLOW, "foo");
        }
    }

    @Test
    public final void shouldNotProduceWhenNotProducerByGroup() {
        Assertions.assertThrows(TopicAuthorizationException.class, () -> {
            try (final Producer<Integer, String> producer = getProducer(LdapServer.NON_PRODUCER_USER_PASS)) {
                produce(producer, TOPIC_WITH_GROUP_ALLOW, "foo");
            }
        });
    }

    @Test
    public final void shouldNotProduceWhenInADeniedGroupEvenIfInAllowedGroup() {
        Assertions.assertThrows(TopicAuthorizationException.class, () -> {
            try (final Producer<Integer, String> producer = getProducer(LdapServer.PRODUCER_WITH_GROUP_DENY_USER_PASS)) {
                produce(producer, TOPIC_WITH_GROUP_ALLOW, "foo");
            }
        });
    }

    @Test
    public final void shouldProduceWhenProducerByGroup() {
        try (final Producer<Integer, String> producer = getProducer(LdapServer.PRODUCER_WITH_GROUP_ALLOW_USER_PASS)) {
            produce(producer, TOPIC_WITH_GROUP_ALLOW, "foo");
        }
    }

    private Producer<Integer, String> getProducer(final String userPass) {
        return getProducer(userPass, userPass);
    }

    private void produce(final Producer<Integer, String> producer, final String topicName, final String recordValue) {
        final ProducerRecord<Integer, String> record = new ProducerRecord<>(topicName, null, recordValue);
        try {
            producer.send(record, (metadata, exception) -> {
                if (exception != null) {
                    throw (exception instanceof RuntimeException) ? (RuntimeException) exception : new RuntimeException(exception);
                }
            }).get(); // Make call synchronous, to be able to get exceptions in time.
        } catch (final InterruptedException | ExecutionException e) {
            final Throwable cause = e.getCause();
            throw (cause instanceof RuntimeException) ? (RuntimeException) cause : new RuntimeException(e);
        }
        producer.flush();
    }

    private void addTopic(final String topicName) {
        final NewTopic newTopic = new NewTopic(topicName, 1, (short) 1);
        try (final Admin admin = getSuperAdmin()) {
            admin.createTopics(Collections.singleton(newTopic));
        }
    }

    private void addProducer(final String topicName, final String principal) {
        addProducer(topicName, principal, AclPermissionType.ALLOW);
    }

    private void addDeniedProducer(final String topicName, final String principal) {
        addProducer(topicName, principal, AclPermissionType.DENY);
    }

    private void addProducer(final String topicName, final String principal, final AclPermissionType permissionType) {
        final AclBinding describeAclBinding = createLiteralBinding(topicName, principal, AclOperation.DESCRIBE, permissionType);
        final AclBinding writeAclBinding = createLiteralBinding(topicName, principal, AclOperation.WRITE, permissionType);
        final Collection<AclBinding> aclBindings = Arrays.asList(describeAclBinding, writeAclBinding);
        try (final Admin admin = getSuperAdmin()) {
            admin.createAcls(aclBindings);
        }
    }

    private AclBinding createLiteralBinding(final String topicName, final String principal, final AclOperation operation, final AclPermissionType permissionType) {
        return createBinding(topicName, PatternType.LITERAL, principal, operation, permissionType);
    }

    private AclBinding createBinding(final String topicName, final PatternType patternType, final String principal, final AclOperation operation, final AclPermissionType permissionType) {
        final ResourcePattern resourcePattern = new ResourcePattern(ResourceType.TOPIC, topicName, patternType);
        final AccessControlEntry accessControlEntry = new AccessControlEntry(principal, ANY_HOST, operation, permissionType);
        return new AclBinding(resourcePattern, accessControlEntry);
    }

    private static String assertValidUsernameAndPassword(final String s) {
        /* Enforcing, in order to not have to deal with escaping for the JAAS config. */
        for (final char c : s.toCharArray()) {
            if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-')) {
                throw new RuntimeException(
                "Only letters, digits and hyphens allowed in usernames and passwords.");
            }
        }
        return s;
    }

    private Admin getSuperAdmin() {
        return getAdmin("kafka", "kafka");
    }

    private Admin getAdmin(final String username, final String password) {
        return AdminClient.create(getSaslConfig(username, password));
    }

    private Producer<Integer, String> getProducer(final String username, final String password) {
        final Map<String, Object> config = K3aTestUtils.producerProps(kafka);
        config.putAll(getSaslConfig(username, password));
        return new KafkaProducer<>(config);
    }

    private Map<String, Object> getSaslConfig(final String username, final String password) {
        final Map<String, Object> map = new HashMap<>();
        map.put(CommonClientConfigs.BOOTSTRAP_SERVERS_CONFIG, kafka.getBootstrapServersForAdditionalPort(0));
        map.put("security.protocol", "SASL_PLAINTEXT");
        map.put("sasl.mechanism", "PLAIN");
        map.put("sasl.jaas.config",
                "org.apache.kafka.common.security.plain.PlainLoginModule required username="
                + assertValidUsernameAndPassword(username)
                + " password=" + assertValidUsernameAndPassword(password) + ";");
        return map;
    }

}
