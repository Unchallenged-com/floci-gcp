package io.floci.gcp.services.cloudlogging;

import com.google.logging.v2.ListLogEntriesRequest;
import com.google.logging.v2.LoggingServiceV2Grpc;
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
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
class CloudLoggingListFilterIntegrationTest {
    private static final String PARENT = "projects/test-project";

    @TestHTTPResource
    URI endpoint;

    @Test
    void restAndGrpcListOnlyWhatTheFilterMatches() throws Exception {
        String id = "filter-" + UUID.randomUUID();
        String log = PARENT + "/logs/" + id;
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("logName", log, "entries", List.of(
                        Map.of("severity", "ERROR", "jsonPayload", Map.of("user", "alice")),
                        Map.of("severity", "INFO", "jsonPayload", Map.of("user", "bob")))))
                .post("/v2/entries:write").then().statusCode(200);

        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of(PARENT),
                        "filter", "log_id(\"" + id + "\") AND (jsonPayload.user=alice OR severity<INFO)"))
                .post("/v2/entries:list")
                .then().statusCode(200).body("entries", hasSize(1)).body("entries[0].jsonPayload.user", equalTo("alice"));

        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            LoggingServiceV2Grpc.LoggingServiceV2BlockingStub logging = LoggingServiceV2Grpc.newBlockingStub(channel)
                    .withDeadlineAfter(10, TimeUnit.SECONDS);
            assertEquals(1, logging.listLogEntries(ListLogEntriesRequest.newBuilder().addResourceNames(PARENT)
                    .setFilter("logName=\"" + log + "\" AND NOT jsonPayload.user=alice").build()).getEntriesCount());
            StatusRuntimeException error = assertThrows(StatusRuntimeException.class, () ->
                    logging.listLogEntries(ListLogEntriesRequest.newBuilder().addResourceNames(PARENT)
                            .setFilter("logName=\"" + log + "\" AND textPayload=~\"secret.*\"").build()));
            assertEquals(Status.Code.INVALID_ARGUMENT, error.getStatus().getCode());
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }

        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of(PARENT), "filter", "logName=\"" + log + "\" AND sample(insertId, 0.5)"))
                .post("/v2/entries:list")
                .then().statusCode(400).body("error.status", equalTo("INVALID_ARGUMENT"));
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of(PARENT), "pageSize", -1))
                .post("/v2/entries:list")
                .then().statusCode(400).body("error.status", equalTo("INVALID_ARGUMENT"));
    }
}
