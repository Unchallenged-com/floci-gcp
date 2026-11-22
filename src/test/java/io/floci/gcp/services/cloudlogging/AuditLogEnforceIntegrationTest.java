package io.floci.gcp.services.cloudlogging;

import com.google.logging.v2.ConfigServiceV2Grpc;
import com.google.logging.v2.CreateSinkRequest;
import com.google.logging.v2.LogSink;
import io.floci.gcp.services.credentials.CredentialTokenService;
import io.floci.gcp.testing.IamEnforceProfile;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
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
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(IamEnforceProfile.class)
class AuditLogEnforceIntegrationTest {

    @Inject
    CredentialTokenService tokens;
    @TestHTTPResource
    URI endpoint;

    @Test
    void writesRefusedByIamAreRecordedAsDenied() throws Exception {
        String project = project();
        String caller = "intruder@" + project + ".iam.gserviceaccount.com";
        String token = tokens.mintImpersonatedToken(caller, Instant.now().plusSeconds(300)).getTokenValue();

        given().header("Authorization", "Bearer " + token).contentType("application/json")
                .body(Map.of("accountId", "backdoor"))
                .when().post("/v1/projects/" + project + "/serviceAccounts").then().statusCode(403);

        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            Metadata headers = new Metadata();
            headers.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + token);
            StatusRuntimeException denied = assertThrows(StatusRuntimeException.class, () ->
                    ConfigServiceV2Grpc.newBlockingStub(channel)
                            .withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
                            .withDeadlineAfter(10, TimeUnit.SECONDS)
                            .createSink(CreateSinkRequest.newBuilder().setParent("projects/" + project)
                                    .setSink(LogSink.newBuilder().setName("exfil")
                                            .setDestination("storage.googleapis.com/elsewhere")).build()));
            assertEquals(Status.Code.PERMISSION_DENIED, denied.getStatus().getCode());
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("google.iam.admin.v1.CreateServiceAccount", "google.logging.v2.ConfigServiceV2.CreateSink"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());
        for (Map<String, Object> entry : entries) {
            JsonPath audit = payload(entry);
            assertEquals(7, audit.getInt("status.code"));
            // proto3 JSON leaves out a false granted, as one real denied entry does.
            assertFalse(Boolean.TRUE.equals(audit.get("authorizationInfo[0].granted")));
            assertEquals(caller, audit.getString("authenticationInfo.principalEmail"));
            assertEquals("ERROR", new JsonPath(toJson(entry)).getString("severity"));
        }
    }

    @Test
    void readsRefusedByIamAreRecordedWhenTheirLogTypeIsEnabled() {
        String project = project();
        String secret = "projects/" + project + "/secrets/vault";
        given().contentType("application/json").body(Map.of("replication", Map.of("automatic", Map.of())))
                .when().post("/v1/projects/" + project + "/secrets?secretId=vault").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("auditConfigs", List.of(Map.of("service", "allServices",
                        "auditLogConfigs", List.of(Map.of("logType", "DATA_READ"))))), "updateMask", "auditConfigs"))
                .when().post("/v1/projects/" + project + ":setIamPolicy").then().statusCode(200);
        String caller = "reader@" + project + ".iam.gserviceaccount.com";
        String token = tokens.mintImpersonatedToken(caller, Instant.now().plusSeconds(300)).getTokenValue();

        given().urlEncodingEnabled(false).header("Authorization", "Bearer " + token)
                .when().get("/v1/" + secret + "/versions/latest:access").then().statusCode(403);

        List<Map<String, Object>> entries = given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of("projects/" + project), "filter",
                        "logName=\"projects/" + project + "/logs/cloudaudit.googleapis.com%2Fdata_access\""))
                .when().post("/v2/entries:list").then().statusCode(200).extract().jsonPath().getList("entries");
        assertEquals(1, entries.size());
        JsonPath audit = payload(entries.getFirst());
        assertEquals("google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", audit.getString("methodName"));
        assertEquals(7, audit.getInt("status.code"));
        assertEquals(caller, audit.getString("authenticationInfo.principalEmail"));
        assertEquals("ERROR", new JsonPath(toJson(entries.getFirst())).getString("severity"));
    }

    @Test
    void storageReadsRefusedByIamAreRecorded() {
        String project = project();
        String bucket = "audit-deny-" + project.substring("audit-".length());
        given().contentType("application/json").body(Map.of("name", bucket))
                .when().post("/storage/v1/b?project=" + project).then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("auditConfigs", List.of(Map.of("service", "storage.googleapis.com",
                        "auditLogConfigs", List.of(Map.of("logType", "DATA_READ"))))), "updateMask", "auditConfigs"))
                .when().post("/v1/projects/" + project + ":setIamPolicy").then().statusCode(200);
        String caller = "intruder@" + project + ".iam.gserviceaccount.com";
        String token = tokens.mintImpersonatedToken(caller, Instant.now().plusSeconds(300)).getTokenValue();

        given().header("Authorization", "Bearer " + token).queryParam("alt", "media")
                .when().get("/storage/v1/b/" + bucket + "/o/q3.csv").then().statusCode(403);

        List<Map<String, Object>> entries = given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of("projects/" + project), "filter",
                        "logName=\"projects/" + project + "/logs/cloudaudit.googleapis.com%2Fdata_access\""))
                .when().post("/v2/entries:list").then().statusCode(200).extract().jsonPath().getList("entries");
        assertEquals(1, entries.size());
        JsonPath audit = payload(entries.getFirst());
        assertEquals("storage.objects.get", audit.getString("methodName"));
        assertEquals(7, audit.getInt("status.code"));
        assertEquals(caller, audit.getString("authenticationInfo.principalEmail"));
        assertEquals("ERROR", new JsonPath(toJson(entries.getFirst())).getString("severity"));
    }
}
