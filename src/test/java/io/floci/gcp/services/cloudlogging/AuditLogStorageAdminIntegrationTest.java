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

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.toJson;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class AuditLogStorageAdminIntegrationTest {

    @Inject
    CredentialTokenService tokens;

    @Test
    void bucketChangesWriteAdminActivityEntries() {
        String project = project();
        String bucket = "audit-admin-" + UUID.randomUUID().toString().substring(0, 8);
        String caller = "ops@" + project + ".iam.gserviceaccount.com";
        String authorization = "Bearer " + tokens.mintImpersonatedToken(caller, Instant.now().plusSeconds(300))
                .getTokenValue();

        given().header("Authorization", authorization).contentType("application/json")
                .body(Map.of("name", bucket, "location", "US-CENTRAL1"))
                .when().post("/storage/v1/b?project=" + project).then().statusCode(200);
        given().header("Authorization", authorization).contentType("application/json")
                .body(Map.of("labels", Map.of("team", "data")))
                .when().patch("/storage/v1/b/" + bucket).then().statusCode(200);
        given().header("Authorization", authorization).contentType("application/json")
                .body(Map.of("bindings", List.of(Map.of("role", "roles/storage.objectViewer",
                        "members", List.of("allUsers")))))
                .when().put("/storage/v1/b/" + bucket + "/iam").then().statusCode(200);
        given().header("Authorization", authorization).when().delete("/storage/v1/b/" + bucket).then().statusCode(204);

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("storage.buckets.create", "storage.buckets.update", "storage.setIamPermissions",
                "storage.buckets.delete"), entries.stream().map(entry -> payload(entry).getString("methodName")).toList());

        JsonPath created = payload(entries.getFirst());
        assertEquals("storage.googleapis.com", created.getString("serviceName"));
        assertEquals("projects/_/buckets/" + bucket, created.getString("resourceName"));
        assertEquals("storage.buckets.create", created.getString("authorizationInfo[0].permission"));
        assertNull(created.get("authorizationInfo[0].permissionType"));
        assertEquals(caller, created.getString("authenticationInfo.principalEmail"));
        JsonPath createdEntry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("NOTICE", createdEntry.getString("severity"));
        assertEquals("gcs_bucket", createdEntry.getString("resource.type"));
        assertEquals(Map.of("bucket_name", bucket, "location", "us-central1", "project_id", project),
                createdEntry.getMap("resource.labels"));

        JsonPath policy = payload(entries.get(2));
        assertEquals("storage.buckets.setIamPolicy", policy.getString("authorizationInfo[0].permission"));
        assertEquals("type.googleapis.com/google.iam.v1.logging.AuditData", policy.getString("serviceData.'@type'"));
        // The replaced policy also drops the creator's bootstrap grant, which the delta reports as a REMOVE.
        assertTrue(policy.getList("serviceData.policyDelta.bindingDeltas").contains(
                Map.of("action", "ADD", "role", "roles/storage.objectViewer", "member", "allUsers")));
        assertEquals("storage.buckets.delete", payload(entries.get(3)).getString("authorizationInfo[0].permission"));
    }
}
