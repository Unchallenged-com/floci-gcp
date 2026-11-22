package io.floci.gcp.services.cloudlogging;

import io.floci.gcp.services.credentials.CredentialTokenService;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.toJson;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class AuditLogStorageIntegrationTest {

    @Inject
    CredentialTokenService tokens;

    @Test
    void storageCallsWriteDataAccessEntriesOfTheirEnabledTypes() {
        String project = project();
        String bucket = "audit-" + UUID.randomUUID().toString().substring(0, 8);
        String caller = "etl@" + project + ".iam.gserviceaccount.com";
        String authorization = "Bearer " + tokens.mintImpersonatedToken(caller, Instant.now().plusSeconds(300))
                .getTokenValue();
        given().contentType("application/json").body(Map.of("name", bucket, "location", "US-CENTRAL1"))
                .when().post("/storage/v1/b?project=" + project).then().statusCode(200);
        given().header("Authorization", authorization).contentType("text/plain").body("hunter2")
                .queryParam("uploadType", "media").queryParam("name", "before.txt")
                .when().post("/upload/storage/v1/b/" + bucket + "/o").then().statusCode(200);
        assertTrue(dataAccess(project).isEmpty(), "Data Access logs are disabled by default");

        enable(project, List.of(Map.of("service", "storage.googleapis.com", "auditLogConfigs", List.of(
                Map.of("logType", "ADMIN_READ"), Map.of("logType", "DATA_READ"), Map.of("logType", "DATA_WRITE")))));
        given().header("Authorization", authorization).contentType("text/plain").body("hunter2")
                .queryParam("uploadType", "media").queryParam("name", "secret.txt")
                .when().post("/upload/storage/v1/b/" + bucket + "/o").then().statusCode(200);
        given().header("Authorization", authorization).queryParam("alt", "media")
                .when().get("/storage/v1/b/" + bucket + "/o/secret.txt").then().statusCode(200);
        given().header("Authorization", authorization).when().get("/storage/v1/b/" + bucket + "/o").then().statusCode(200);
        given().header("Authorization", authorization).when().get("/storage/v1/b/" + bucket).then().statusCode(200);
        given().header("Authorization", authorization).when().get("/storage/v1/b/" + bucket + "/iam").then().statusCode(200);
        given().header("Authorization", authorization).queryParam("project", project)
                .when().get("/storage/v1/b").then().statusCode(200);
        given().header("Authorization", authorization).when().delete("/storage/v1/b/" + bucket + "/o/secret.txt")
                .then().statusCode(204);
        given().queryParam("alt", "media").when().get("/storage/v1/b/" + bucket + "/o/before.txt").then().statusCode(200);

        List<Map<String, Object>> entries = dataAccess(project);
        assertEquals(List.of("storage.objects.create", "storage.objects.get", "storage.objects.list",
                "storage.buckets.get", "storage.getIamPermissions", "storage.buckets.list", "storage.objects.delete"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList(),
                "an anonymous read is not recorded");

        JsonPath read = payload(entries.get(1));
        assertEquals("storage.googleapis.com", read.getString("serviceName"));
        assertEquals("projects/_/buckets/" + bucket + "/objects/secret.txt", read.getString("resourceName"));
        assertEquals(caller, read.getString("authenticationInfo.principalEmail"));
        assertEquals("storage.objects.get", read.getString("authorizationInfo[0].permission"));
        assertEquals("projects/_/buckets/" + bucket + "/objects/secret.txt", read.getString("authorizationInfo[0].resource"));
        assertEquals(true, read.getBoolean("authorizationInfo[0].granted"));
        assertNull(read.get("authorizationInfo[0].permissionType"));
        assertEquals(Map.of(), read.getMap("authorizationInfo[0].resourceAttributes"));
        assertEquals(List.of("us-central1"), read.getList("resourceLocation.currentLocations"));
        assertNull(read.get("request"));
        JsonPath readEntry = new JsonPath(toJson(entries.get(1)));
        assertEquals("INFO", readEntry.getString("severity"));
        assertEquals("gcs_bucket", readEntry.getString("resource.type"));
        assertEquals(Map.of("bucket_name", bucket, "location", "us-central1", "project_id", project),
                readEntry.getMap("resource.labels"));

        assertEquals("projects/_/buckets/" + bucket, payload(entries.get(2)).getString("resourceName"));
        assertEquals("storage.buckets.getIamPolicy", payload(entries.get(4)).getString("authorizationInfo[0].permission"));
        assertEquals("projects/_/buckets/*", payload(entries.get(5)).getString("resourceName"));
        assertFalse(toJson(entries).contains("hunter2"), "object data is never logged");
    }

    @Test
    void listLogEntriesIsRecordedWhenLoggingDataReadIsEnabled() {
        String project = project();
        enable(project, List.of(Map.of("service", "logging.googleapis.com",
                "auditLogConfigs", List.of(Map.of("logType", "DATA_READ")))));
        dataAccess(project);

        List<Map<String, Object>> entries = dataAccess(project);
        assertEquals(1, entries.size());
        JsonPath audit = payload(entries.getFirst());
        assertEquals("google.logging.v2.LoggingServiceV2.ListLogEntries", audit.getString("methodName"));
        assertEquals("projects/" + project, audit.getString("resourceName"));
        assertEquals("logging.logEntries.list", audit.getString("authorizationInfo[0].permission"));
        assertEquals("DATA_READ", audit.getString("authorizationInfo[0].permissionType"));
        assertEquals("type.googleapis.com/google.logging.v2.ListLogEntriesRequest", audit.getString("request.'@type'"));
        assertEquals(List.of("projects/" + project), audit.getList("request.resourceNames"));
        assertTrue(audit.getString("request.filter").contains("data_access"));
        JsonPath entry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("audited_resource", entry.getString("resource.type"));
        assertEquals(Map.of("method", "google.logging.v2.LoggingServiceV2.ListLogEntries", "project_id", project,
                "service", "logging.googleapis.com"), entry.getMap("resource.labels"));
    }

    private static void enable(String project, List<Map<String, Object>> auditConfigs) {
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("auditConfigs", auditConfigs), "updateMask", "auditConfigs"))
                .when().post("/v1/projects/" + project + ":setIamPolicy").then().statusCode(200);
    }

    private static List<Map<String, Object>> dataAccess(String project) {
        List<Map<String, Object>> entries = given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of("projects/" + project),
                        "filter", "logName=\"projects/" + project + "/logs/cloudaudit.googleapis.com%2Fdata_access\""))
                .when().post("/v2/entries:list")
                .then().statusCode(200).extract().jsonPath().getList("entries");
        return entries == null ? List.of() : entries;
    }
}
