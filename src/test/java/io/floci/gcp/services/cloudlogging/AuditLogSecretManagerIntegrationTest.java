package io.floci.gcp.services.cloudlogging;

import com.google.cloud.secretmanager.v1.CreateSecretRequest;
import com.google.cloud.secretmanager.v1.DeleteSecretRequest;
import com.google.cloud.secretmanager.v1.Replication;
import com.google.cloud.secretmanager.v1.Secret;
import com.google.cloud.secretmanager.v1.SecretManagerServiceGrpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.toJson;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@QuarkusTest
class AuditLogSecretManagerIntegrationTest {

    @TestHTTPResource
    URI endpoint;

    @Test
    void secretChangesWriteAdminActivityEntries() throws Exception {
        String project = project();
        String base = "/v1/projects/" + project + "/secrets";
        String secret = "projects/" + project + "/secrets/db-password";
        String payload = Base64.getEncoder().encodeToString("hunter2".getBytes());

        given().contentType("application/json").body(Map.of("replication", Map.of("automatic", Map.of())))
                .when().post(base + "?secretId=db-password").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("payload", Map.of("data", payload)))
                .when().post("/v1/" + secret + ":addVersion").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of())
                .when().post("/v1/" + secret + "/versions/1:disable").then().statusCode(200);
        given().contentType("application/json").body(Map.of("labels", Map.of("team", "db")))
                .when().patch("/v1/" + secret + "?updateMask=labels").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("bindings", List.of(Map.of("role", "roles/secretmanager.secretAccessor",
                        "members", List.of("user:attacker@example.com"))))))
                .when().post("/v1/" + secret + ":setIamPolicy").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of())
                .when().post("/v1/" + secret + "/versions/1:destroy").then().statusCode(200);
        given().when().get("/v1/" + secret).then().statusCode(200);

        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            SecretManagerServiceGrpc.SecretManagerServiceBlockingStub secrets = SecretManagerServiceGrpc
                    .newBlockingStub(channel).withDeadlineAfter(10, TimeUnit.SECONDS);
            secrets.createSecret(CreateSecretRequest.newBuilder().setParent("projects/" + project)
                    .setSecretId("api-key").setSecret(Secret.newBuilder().setReplication(Replication.newBuilder()
                            .setAutomatic(Replication.Automatic.getDefaultInstance()))).build());
            secrets.deleteSecret(DeleteSecretRequest.newBuilder().setName(secret).build());
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }

        List<Map<String, Object>> entries = activity(project);
        String prefix = "google.cloud.secretmanager.v1.SecretManagerService.";
        assertEquals(List.of(prefix + "CreateSecret", prefix + "AddSecretVersion", prefix + "DisableSecretVersion",
                prefix + "UpdateSecret", prefix + "SetIamPolicy", prefix + "DestroySecretVersion",
                prefix + "CreateSecret", prefix + "DeleteSecret"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());

        JsonPath created = payload(entries.getFirst());
        assertEquals("secretmanager.googleapis.com", created.getString("serviceName"));
        assertEquals(secret, created.getString("resourceName"));
        assertEquals("secretmanager.secrets.create", created.getString("authorizationInfo[0].permission"));
        assertEquals("ADMIN_WRITE", created.getString("authorizationInfo[0].permissionType"));
        assertEquals("db-password", created.getString("request.secretId"));
        assertEquals("projects/" + project, created.getString("request.parent"));
        JsonPath createdEntry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("NOTICE", createdEntry.getString("severity"));
        assertEquals("audited_resource", createdEntry.getString("resource.type"));
        assertEquals(Map.of("method", prefix + "CreateSecret", "project_id", project,
                "service", "secretmanager.googleapis.com"), createdEntry.getMap("resource.labels"));

        assertEquals(secret, payload(entries.get(1)).getString("request.parent"));
        assertFalse(toJson(entries).contains(payload), "the secret payload is never recorded");
        assertEquals(secret + "/versions/1", payload(entries.get(2)).getString("resourceName"));
        assertEquals("labels", payload(entries.get(3)).getString("request.updateMask"));
        assertEquals(List.of(Map.of("action", "ADD", "role", "roles/secretmanager.secretAccessor",
                "member", "user:attacker@example.com")), payload(entries.get(4)).getList("serviceData.policyDelta.bindingDeltas"));
        assertEquals("api-key", payload(entries.get(6)).getString("request.secretId"));
        assertEquals(secret, payload(entries.get(7)).getString("request.name"));
    }
}
