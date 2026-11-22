package io.floci.gcp.services.cloudlogging;

import com.google.cloud.kms.v1.CreateCryptoKeyRequest;
import com.google.cloud.kms.v1.CreateKeyRingRequest;
import com.google.cloud.kms.v1.CryptoKey;
import com.google.cloud.kms.v1.DestroyCryptoKeyVersionRequest;
import com.google.cloud.kms.v1.KeyManagementServiceGrpc;
import com.google.cloud.kms.v1.KeyRing;
import com.google.cloud.kms.v1.RestoreCryptoKeyVersionRequest;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.toJson;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class AuditLogKmsIntegrationTest {

    @TestHTTPResource
    URI endpoint;

    @Test
    void keyChangesWriteAdminActivityEntries() throws Exception {
        String project = project();
        String location = "projects/" + project + "/locations/us-central1";
        String keyRing = location + "/keyRings/vault";
        String key = keyRing + "/cryptoKeys/backups";
        String version = key + "/cryptoKeyVersions/1";
        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            KeyManagementServiceGrpc.KeyManagementServiceBlockingStub kms = KeyManagementServiceGrpc
                    .newBlockingStub(channel).withDeadlineAfter(10, TimeUnit.SECONDS);
            kms.createKeyRing(CreateKeyRingRequest.newBuilder().setParent(location).setKeyRingId("vault")
                    .setKeyRing(KeyRing.getDefaultInstance()).build());
            kms.createCryptoKey(CreateCryptoKeyRequest.newBuilder().setParent(keyRing).setCryptoKeyId("backups")
                    .setCryptoKey(CryptoKey.newBuilder().setPurpose(CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT))
                    .build());
            kms.destroyCryptoKeyVersion(DestroyCryptoKeyVersionRequest.newBuilder().setName(version).build());
            kms.restoreCryptoKeyVersion(RestoreCryptoKeyVersionRequest.newBuilder().setName(version).build());
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("CreateKeyRing", "CreateCryptoKey", "DestroyCryptoKeyVersion", "RestoreCryptoKeyVersion"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());

        JsonPath ring = payload(entries.getFirst());
        assertEquals("cloudkms.googleapis.com", ring.getString("serviceName"));
        assertEquals(keyRing, ring.getString("resourceName"));
        assertEquals("cloudkms.keyRings.create", ring.getString("authorizationInfo[0].permission"));
        assertEquals("ADMIN_WRITE", ring.getString("authorizationInfo[0].permissionType"));
        assertEquals("vault", ring.getString("request.keyRingId"));
        JsonPath ringEntry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("NOTICE", ringEntry.getString("severity"));
        assertEquals("cloudkms_keyring", ringEntry.getString("resource.type"));
        assertEquals(Map.of("project_id", project, "location", "us-central1", "key_ring_id", "vault"),
                ringEntry.getMap("resource.labels"));

        assertEquals("cloudkms_cryptokey", new JsonPath(toJson(entries.get(1))).getString("resource.type"));
        JsonPath destroyed = new JsonPath(toJson(entries.get(2)));
        assertEquals("cloudkms_cryptokeyversion", destroyed.getString("resource.type"));
        assertEquals("1", destroyed.getString("resource.labels.crypto_key_version_id"));
        assertEquals("cloudkms.cryptoKeyVersions.destroy", payload(entries.get(2)).getString("authorizationInfo[0].permission"));
    }
}
