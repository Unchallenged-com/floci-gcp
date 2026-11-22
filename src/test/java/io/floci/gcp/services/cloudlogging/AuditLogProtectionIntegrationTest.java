package io.floci.gcp.services.cloudlogging;

import com.google.logging.v2.LogEntry;
import com.google.logging.v2.LoggingServiceV2Grpc;
import com.google.logging.v2.WriteLogEntriesRequest;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
class AuditLogProtectionIntegrationTest {

    @TestHTTPResource
    URI endpoint;

    @Test
    void callersCannotWriteAuditLogsOrDeleteTheRequiredOnes() throws Exception {
        String project = project();
        String activityLog = "projects/" + project + "/logs/cloudaudit.googleapis.com%2Factivity";
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("bindings", List.of(Map.of("role", "roles/viewer",
                        "members", List.of("user:a@example.com"))))))
                .when().post("/v1/projects/" + project + ":setIamPolicy").then().statusCode(200);

        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("logName", activityLog, "entries", List.of(Map.of("textPayload", "forged"))))
                .when().post("/v2/entries:write")
                .then().statusCode(400).body("error.status", equalTo("INVALID_ARGUMENT"));
        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            StatusRuntimeException refused = assertThrows(StatusRuntimeException.class, () ->
                    LoggingServiceV2Grpc.newBlockingStub(channel).withDeadlineAfter(10, TimeUnit.SECONDS)
                            .writeLogEntries(WriteLogEntriesRequest.newBuilder()
                                    .setLogName("projects/" + project + "/logs/cloudaudit.googleapis.com%2Fdata_access")
                                    .addEntries(LogEntry.newBuilder().setTextPayload("forged")).build()));
            assertEquals(Status.Code.INVALID_ARGUMENT, refused.getStatus().getCode());
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }

        given().when().delete("/v2/projects/" + project + "/logs/cloudaudit.googleapis.com%2Factivity")
                .then().statusCode(400).body("error.status", equalTo("INVALID_ARGUMENT"));
        assertEquals(1, activity(project).size(), "the activity entry is kept and no forged entry was added");
    }
}
