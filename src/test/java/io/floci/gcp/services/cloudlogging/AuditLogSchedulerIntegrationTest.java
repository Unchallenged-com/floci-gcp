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
class AuditLogSchedulerIntegrationTest {

    @Test
    void jobChangesWriteAdminActivityEntries() {
        String project = project();
        String parent = "projects/" + project + "/locations/us-central1";
        String job = parent + "/jobs/nightly";
        given().contentType("application/json")
                .body(Map.of("name", job, "schedule", "0 3 * * *", "timeZone", "UTC",
                        "httpTarget", Map.of("uri", "http://example.com/backup")))
                .when().post("/v1/" + parent + "/jobs").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of())
                .when().post("/v1/" + job + ":pause").then().statusCode(200);
        given().when().delete("/v1/" + job).then().statusCode(200);

        List<Map<String, Object>> entries = activity(project);
        String prefix = "google.cloud.scheduler.v1.CloudScheduler.";
        assertEquals(List.of(prefix + "CreateJob", prefix + "PauseJob", prefix + "DeleteJob"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());
        JsonPath created = payload(entries.getFirst());
        assertEquals("cloudscheduler.googleapis.com", created.getString("serviceName"));
        assertEquals(job, created.getString("resourceName"));
        assertEquals("cloudscheduler.jobs.create", created.getString("authorizationInfo[0].permission"));
        assertEquals(parent, created.getString("request.parent"));
        assertEquals("0 3 * * *", created.getString("request.job.schedule"));
        JsonPath createdEntry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("cloud_scheduler_job", createdEntry.getString("resource.type"));
        assertEquals(Map.of("project_id", project, "location", "us-central1", "job_id", "nightly"),
                createdEntry.getMap("resource.labels"));
        assertEquals(job, payload(entries.get(2)).getString("request.name"));
    }
}
