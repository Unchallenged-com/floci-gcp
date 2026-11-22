package io.floci.gcp.services.cloudlogging;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.toJson;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class AuditLogCloudRunIntegrationTest {

    @Test
    void serviceChangesWriteAdminActivityEntries() {
        String project = project();
        String parent = "projects/" + project + "/locations/us-central1";
        String service = parent + "/services/web";
        given().contentType("application/json").queryParam("serviceId", "web")
                .body("{\"template\":{\"containers\":[{\"image\":\"gcr.io/" + project + "/web:latest\"}]}}")
                .when().post("/v2/" + parent + "/services").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("bindings", List.of(Map.of("role", "roles/run.invoker",
                        "members", List.of("allUsers"))))))
                .when().post("/v2/" + service + ":setIamPolicy").then().statusCode(200);
        given().when().delete("/v2/" + service).then().statusCode(200);

        List<Map<String, Object>> entries = activity(project);
        String prefix = "google.cloud.run.v2.Services.";
        assertEquals(List.of(prefix + "CreateService", prefix + "SetIamPolicy", prefix + "DeleteService"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());
        JsonPath created = payload(entries.getFirst());
        assertEquals("run.googleapis.com", created.getString("serviceName"));
        assertEquals(service, created.getString("resourceName"));
        assertEquals("run.services.create", created.getString("authorizationInfo[0].permission"));
        assertEquals("web", created.getString("request.serviceId"));
        JsonPath createdEntry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("cloud_run_revision", createdEntry.getString("resource.type"));
        assertEquals(Map.of("project_id", project, "service_name", "web", "revision_name", "", "location", "us-central1"),
                createdEntry.getMap("resource.labels"));
        assertEquals(List.of(Map.of("action", "ADD", "role", "roles/run.invoker", "member", "allUsers")),
                payload(entries.get(1)).getList("serviceData.policyDelta.bindingDeltas"));
    }
}
