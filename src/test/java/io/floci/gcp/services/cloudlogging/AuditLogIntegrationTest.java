package io.floci.gcp.services.cloudlogging;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.logging.v2.ConfigServiceV2Grpc;
import com.google.logging.v2.CreateSinkRequest;
import com.google.logging.v2.DeleteSinkRequest;
import com.google.logging.v2.LogSink;
import com.google.logging.v2.UpdateSinkRequest;
import com.google.protobuf.FieldMask;
import io.floci.gcp.services.credentials.CredentialTokenService;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class AuditLogIntegrationTest {
    private static final String AUDIT_LOG_TYPE = "type.googleapis.com/google.cloud.audit.AuditLog";
    private static final String USER_AGENT = "google-cloud-sdk gcloud/550.0.0 command/gcloud.iam.service-accounts.create";

    @Inject
    CredentialTokenService tokens;
    @TestHTTPResource
    URI endpoint;

    @Test
    void serviceAccountLifecycleWritesAdminActivityEntries() {
        String project = project();
        String caller = "admin@" + project + ".iam.gserviceaccount.com";
        String authorization = "Bearer " + tokens.mintImpersonatedToken(caller, Instant.now().plusSeconds(300))
                .getTokenValue();
        String accounts = "/v1/projects/" + project + "/serviceAccounts";
        String email = "builder@" + project + ".iam.gserviceaccount.com";
        String account = accounts + "/" + email;

        String uniqueId = given().header("Authorization", authorization).header("User-Agent", USER_AGENT)
                .contentType("application/json")
                .body(Map.of("accountId", "builder", "serviceAccount", Map.of("displayName", "Builder")))
                .when().post(accounts).then().statusCode(200).extract().path("uniqueId");
        given().when().get(account).then().statusCode(200);
        String keyName = given().contentType("application/json").body(Map.of())
                .when().post(account + "/keys").then().statusCode(200).extract().path("name");
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of())
                .when().post(account + ":disable").then().statusCode(200);
        given().contentType("application/json")
                .body(Map.of("serviceAccount", Map.of("description", "CI"), "updateMask", "description"))
                .when().patch(account).then().statusCode(200);
        given().when().delete("/v1/" + keyName).then().statusCode(200);
        given().when().delete(account).then().statusCode(200);

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("google.iam.admin.v1.CreateServiceAccount", "google.iam.admin.v1.CreateServiceAccountKey",
                "google.iam.admin.v1.DisableServiceAccount", "google.iam.admin.v1.PatchServiceAccount",
                "google.iam.admin.v1.DeleteServiceAccountKey", "google.iam.admin.v1.DeleteServiceAccount"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());

        JsonPath create = payload(entries.getFirst());
        assertEquals(AUDIT_LOG_TYPE, create.getString("'@type'"));
        assertEquals("iam.googleapis.com", create.getString("serviceName"));
        assertEquals("projects/" + project, create.getString("resourceName"));
        assertEquals(Map.of(), create.getMap("status"));
        assertEquals(caller, create.getString("authenticationInfo.principalEmail"));
        assertEquals("serviceAccount:" + caller, create.getString("authenticationInfo.principalSubject"));
        assertEquals(USER_AGENT, create.getString("requestMetadata.callerSuppliedUserAgent"));
        assertFalse(create.getString("requestMetadata.callerIp").isEmpty());
        assertNotNull(create.getString("requestMetadata.requestAttributes.time"));
        assertEquals("iam.serviceAccounts.create", create.getString("authorizationInfo[0].permission"));
        assertEquals(true, create.getBoolean("authorizationInfo[0].granted"));
        assertEquals("ADMIN_WRITE", create.getString("authorizationInfo[0].permissionType"));
        assertEquals("type.googleapis.com/google.iam.admin.v1.CreateServiceAccountRequest",
                create.getString("request.'@type'"));
        assertEquals("builder", create.getString("request.account_id"));
        assertEquals("Builder", create.getString("request.service_account.display_name"));

        JsonPath entry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("NOTICE", entry.getString("severity"));
        assertEquals("projects/" + project + "/logs/cloudaudit.googleapis.com%2Factivity", entry.getString("logName"));
        assertEquals("service_account", entry.getString("resource.type"));
        assertEquals(Map.of("email_id", email, "project_id", project, "unique_id", uniqueId),
                entry.getMap("resource.labels"));

        assertEquals("projects/-/serviceAccounts/" + uniqueId, payload(entries.get(1)).getString("resourceName"));
        assertEquals("iam.serviceAccountKeys.create", payload(entries.get(1)).getString("authorizationInfo[0].permission"));
        assertEquals("projects/-/serviceAccounts/" + uniqueId, payload(entries.get(1)).getString("authorizationInfo[0].resource"));
        JsonPath deleted = new JsonPath(toJson(entries.getLast()));
        assertEquals(uniqueId, deleted.getString("resource.labels.unique_id"));
    }

    @Test
    void projectPolicyChangesRecordTheirBindingDeltas() {
        String project = project();
        String base = "/v1/projects/" + project;
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("bindings", List.of(
                        Map.of("role", "roles/viewer", "members", List.of("user:old@example.com"))))))
                .when().post(base + ":setIamPolicy").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("bindings", List.of(
                        Map.of("role", "roles/owner", "members", List.of("user:new@example.com"))))))
                .when().post(base + ":setIamPolicy").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of())
                .when().post(base + ":getIamPolicy").then().statusCode(200);

        List<Map<String, Object>> entries = activity(project);
        assertEquals(2, entries.size());
        JsonPath second = payload(entries.get(1));
        assertEquals("cloudresourcemanager.googleapis.com", second.getString("serviceName"));
        assertEquals("SetIamPolicy", second.getString("methodName"));
        assertEquals("projects/" + project, second.getString("resourceName"));
        assertEquals("resourcemanager.projects.setIamPolicy", second.getString("authorizationInfo[0].permission"));
        assertEquals("cloudresourcemanager.googleapis.com/Project",
                second.getString("authorizationInfo[0].resourceAttributes.type"));
        assertEquals("type.googleapis.com/google.iam.v1.logging.AuditData", second.getString("serviceData.'@type'"));
        assertEquals(List.of(
                Map.of("action", "ADD", "role", "roles/owner", "member", "user:new@example.com"),
                Map.of("action", "REMOVE", "role", "roles/viewer", "member", "user:old@example.com")),
                second.getList("serviceData.policyDelta.bindingDeltas"));
        assertEquals("type.googleapis.com/google.iam.v1.SetIamPolicyRequest", second.getString("request.'@type'"));
        assertEquals(project, second.getString("request.resource"));
        assertEquals("roles/owner", second.getString("response.bindings[0].role"));
        assertEquals("project", new JsonPath(toJson(entries.get(1))).getString("resource.type"));
    }

    @Test
    void sinkChangesOverGrpcAndRestWriteAdminActivityEntries() throws Exception {
        String project = project();
        String parent = "projects/" + project;
        String grpcSink = "grpc-" + UUID.randomUUID().toString().substring(0, 8);
        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .userAgent("grpc-java-test").usePlaintext().build();
        try {
            ConfigServiceV2Grpc.ConfigServiceV2BlockingStub config = ConfigServiceV2Grpc.newBlockingStub(channel)
                    .withDeadlineAfter(10, TimeUnit.SECONDS);
            LogSink sink = LogSink.newBuilder().setName(grpcSink)
                    .setDestination("storage.googleapis.com/audit-" + project).build();
            config.createSink(CreateSinkRequest.newBuilder().setParent(parent).setSink(sink)
                    .setUniqueWriterIdentity(true).build());
            config.updateSink(UpdateSinkRequest.newBuilder().setSinkName(parent + "/sinks/" + grpcSink)
                    .setSink(sink.toBuilder().setDisabled(true)).setUpdateMask(FieldMask.newBuilder().addPaths("disabled"))
                    .setUniqueWriterIdentity(true).build());
            config.deleteSink(DeleteSinkRequest.newBuilder().setSinkName(parent + "/sinks/" + grpcSink).build());
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("name", "rest-sink", "destination", "storage.googleapis.com/audit-" + project))
                .when().post("/v2/" + parent + "/sinks?uniqueWriterIdentity=true").then().statusCode(200);
        given().when().get("/v2/" + parent + "/sinks/rest-sink").then().statusCode(200);

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("google.logging.v2.ConfigServiceV2.CreateSink", "google.logging.v2.ConfigServiceV2.UpdateSink",
                "google.logging.v2.ConfigServiceV2.DeleteSink", "google.logging.v2.ConfigServiceV2.CreateSink"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());
        JsonPath created = payload(entries.getFirst());
        assertEquals("logging.googleapis.com", created.getString("serviceName"));
        assertEquals(parent + "/sinks/" + grpcSink, created.getString("resourceName"));
        assertEquals("logging.sinks.create", created.getString("authorizationInfo[0].permission"));
        assertEquals("logging.googleapis.com/LogSink", created.getString("authorizationInfo[0].resourceAttributes.type"));
        assertEquals("type.googleapis.com/google.logging.v2.CreateSinkRequest", created.getString("request.'@type'"));
        assertEquals(parent, created.getString("request.parent"));
        assertEquals(true, created.getBoolean("request.uniqueWriterIdentity"));
        assertTrue(created.getString("requestMetadata.callerSuppliedUserAgent").contains("grpc-java-test"));
        assertEquals(Map.of("project_id", project, "destination", "", "name", grpcSink),
                new JsonPath(toJson(entries.getFirst())).getMap("resource.labels"));
        assertEquals("disabled", payload(entries.get(1)).getString("request.updateMask"));
        assertEquals(parent + "/sinks/" + grpcSink, payload(entries.get(2)).getString("request.sinkName"));
        JsonPath rest = payload(entries.get(3));
        assertEquals(parent, rest.getString("request.parent"));
        assertEquals("rest-sink", rest.getString("request.sink.name"));
        assertEquals(true, rest.getBoolean("request.uniqueWriterIdentity"));
    }

    @Test
    void failedWritesAreRecordedWithTheirStatus() {
        String project = project();
        given().when().delete("/v1/projects/" + project + "/serviceAccounts/missing@" + project
                + ".iam.gserviceaccount.com").then().statusCode(404);

        List<Map<String, Object>> entries = activity(project);
        assertEquals(1, entries.size());
        JsonPath payload = payload(entries.getFirst());
        assertEquals("google.iam.admin.v1.DeleteServiceAccount", payload.getString("methodName"));
        assertEquals(5, payload.getInt("status.code"));
        assertFalse(payload.getString("status.message").isEmpty());
        assertEquals("ERROR", new JsonPath(toJson(entries.getFirst())).getString("severity"));
        assertEquals(Map.of(), payload.getMap("authenticationInfo"));
    }

    static String project() {
        return "audit-" + UUID.randomUUID().toString().substring(0, 8);
    }

    static List<Map<String, Object>> activity(String project) {
        return given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of("projects/" + project),
                        "filter", "logName=\"projects/" + project + "/logs/cloudaudit.googleapis.com%2Factivity\""))
                .when().post("/v2/entries:list")
                .then().statusCode(200).extract().jsonPath().getList("entries");
    }

    static JsonPath payload(Map<String, Object> entry) {
        return new JsonPath(toJson(entry.get("protoPayload")));
    }

    static String toJson(Object value) {
        try {
            return new ObjectMapper().writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
    }
}
