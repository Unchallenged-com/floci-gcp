package io.floci.gcp.services.cloudlogging;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.toJson;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class AuditLogLoggingConfigIntegrationTest {

    @Test
    void metricChangesAndLogDeletionWriteAdminActivityEntries() {
        String project = project();
        String metrics = "/v2/projects/" + project + "/metrics";
        given().contentType("application/json").body(Map.of("name", "errors", "filter", "severity>=ERROR"))
                .when().post(metrics).then().statusCode(200);
        given().contentType("application/json").body(Map.of("name", "errors", "filter", "severity>=WARNING"))
                .when().put(metrics + "/errors").then().statusCode(200);
        given().when().delete(metrics + "/errors").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("logName", "projects/" + project + "/logs/app", "entries", List.of(Map.of("textPayload", "x"))))
                .when().post("/v2/entries:write").then().statusCode(200);
        given().when().delete("/v2/projects/" + project + "/logs/app").then().statusCode(200);

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("google.logging.v2.MetricsServiceV2.CreateLogMetric",
                "google.logging.v2.MetricsServiceV2.UpdateLogMetric", "google.logging.v2.MetricsServiceV2.DeleteLogMetric",
                "google.logging.v2.LoggingServiceV2.DeleteLog"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());

        JsonPath created = payload(entries.getFirst());
        assertEquals("projects/" + project + "/metrics/errors", created.getString("resourceName"));
        assertEquals("logging.logMetrics.create", created.getString("authorizationInfo[0].permission"));
        assertEquals("type.googleapis.com/google.logging.v2.CreateLogMetricRequest", created.getString("request.'@type'"));
        assertEquals("projects/" + project, created.getString("request.parent"));
        assertEquals("errors", created.getString("request.metric.name"));
        JsonPath createdEntry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("metric", createdEntry.getString("resource.type"));
        assertEquals(Map.of("name", "logging.googleapis.com/user/errors", "project_id", project),
                createdEntry.getMap("resource.labels"));

        JsonPath deleted = payload(entries.getLast());
        assertEquals("projects/" + project + "/logs/app", deleted.getString("resourceName"));
        assertEquals("logging.logs.delete", deleted.getString("authorizationInfo[0].permission"));
        JsonPath deletedEntry = new JsonPath(toJson(entries.getLast()));
        assertEquals("logging_log", deletedEntry.getString("resource.type"));
        assertEquals(Map.of("name", "app", "project_id", project), deletedEntry.getMap("resource.labels"));
    }

    @Test
    void organizationSinkChangesAreRecordedInTheOrganizationsActivityLog() {
        String organization = "organizations/8" + Math.abs(UUID.randomUUID().getLeastSignificantBits() % 100000000L);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("name", "all-audit", "destination", "storage.googleapis.com/org-audit"))
                .when().post("/v2/" + organization + "/sinks").then().statusCode(200);
        given().when().delete("/v2/" + organization + "/sinks/all-audit").then().statusCode(200);

        List<Map<String, Object>> entries = given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of(organization),
                        "filter", "logName=\"" + organization + "/logs/cloudaudit.googleapis.com%2Factivity\""))
                .when().post("/v2/entries:list").then().statusCode(200).extract().jsonPath().getList("entries");
        assertEquals(List.of("google.logging.v2.ConfigServiceV2.CreateSink", "google.logging.v2.ConfigServiceV2.DeleteSink"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());
        assertEquals(organization + "/sinks/all-audit", payload(entries.getFirst()).getString("resourceName"));
        assertEquals(Map.of("destination", "", "name", "all-audit"),
                new JsonPath(toJson(entries.getFirst())).getMap("resource.labels"));
    }
}
