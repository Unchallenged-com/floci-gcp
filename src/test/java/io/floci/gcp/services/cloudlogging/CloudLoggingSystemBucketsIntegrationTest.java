package io.floci.gcp.services.cloudlogging;

import com.google.logging.v2.ConfigServiceV2Grpc;
import com.google.logging.v2.DeleteBucketRequest;
import com.google.logging.v2.DeleteSinkRequest;
import com.google.logging.v2.GetBucketRequest;
import com.google.logging.v2.GetSinkRequest;
import com.google.logging.v2.LifecycleState;
import com.google.logging.v2.ListBucketsRequest;
import com.google.logging.v2.ListSinksRequest;
import com.google.logging.v2.LogBucket;
import com.google.logging.v2.LogExclusion;
import com.google.logging.v2.LogSink;
import com.google.logging.v2.UpdateBucketRequest;
import com.google.logging.v2.UpdateSinkRequest;
import com.google.protobuf.FieldMask;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.toJson;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class CloudLoggingSystemBucketsIntegrationTest {

    private static final String REQUIRED_FILTER = "LOG_ID(\"cloudaudit.googleapis.com/activity\") OR "
            + "LOG_ID(\"externalaudit.googleapis.com/activity\") OR LOG_ID(\"cloudaudit.googleapis.com/system_event\") OR "
            + "LOG_ID(\"externalaudit.googleapis.com/system_event\") OR "
            + "LOG_ID(\"cloudaudit.googleapis.com/access_transparency\") OR "
            + "LOG_ID(\"externalaudit.googleapis.com/access_transparency\")";
    private static final String DEFAULT_FILTER = "NOT LOG_ID(\"cloudaudit.googleapis.com/activity\") AND "
            + "NOT LOG_ID(\"externalaudit.googleapis.com/activity\") AND "
            + "NOT LOG_ID(\"cloudaudit.googleapis.com/system_event\") AND "
            + "NOT LOG_ID(\"externalaudit.googleapis.com/system_event\") AND "
            + "NOT LOG_ID(\"cloudaudit.googleapis.com/access_transparency\") AND "
            + "NOT LOG_ID(\"externalaudit.googleapis.com/access_transparency\")";

    @TestHTTPResource
    URI endpoint;

    @Test
    void everyProjectListsItsRequiredAndDefaultBucketsAndSinks() throws Exception {
        String parent = "projects/" + project();
        String buckets = "/v2/" + parent + "/locations/global/buckets";
        given().when().get(buckets).then().statusCode(200)
                .body("buckets.name", equalTo(List.of(parent + "/locations/global/buckets/_Required",
                        parent + "/locations/global/buckets/_Default")))
                .body("buckets.description", equalTo(List.of("Audit bucket", "Default bucket")))
                .body("buckets.retentionDays", equalTo(List.of(400, 30)))
                .body("buckets.locked", equalTo(Arrays.asList(true, null)))
                .body("buckets.lifecycleState", equalTo(List.of("ACTIVE", "ACTIVE")));
        given().when().get("/v2/" + parent + "/locations/-/buckets").then().statusCode(200)
                .body("buckets.size()", equalTo(2));
        given().when().get("/v2/" + parent + "/locations/us-central1/buckets").then().statusCode(200)
                .body("buckets", equalTo(null));
        given().when().get(buckets + "/missing").then().statusCode(404);

        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            ConfigServiceV2Grpc.ConfigServiceV2BlockingStub config = ConfigServiceV2Grpc.newBlockingStub(channel)
                    .withDeadlineAfter(10, TimeUnit.SECONDS);
            LogBucket required = config.getBucket(GetBucketRequest.newBuilder()
                    .setName(parent + "/locations/global/buckets/_Required").build());
            assertEquals(400, required.getRetentionDays());
            assertEquals(LifecycleState.ACTIVE, required.getLifecycleState());
            assertTrue(required.getLocked());
            // "This is not set for any of the default buckets" (logging_config.proto).
            assertFalse(required.hasCreateTime());
            assertEquals(2, config.listBuckets(ListBucketsRequest.newBuilder()
                    .setParent(parent + "/locations/global").build()).getBucketsCount());

            List<LogSink> sinks = config.listSinks(ListSinksRequest.newBuilder().setParent(parent).build())
                    .getSinksList();
            assertEquals(List.of("_Required", "_Default"), sinks.stream().map(LogSink::getName).toList());
            assertEquals("logging.googleapis.com/" + parent + "/locations/global/buckets/_Default",
                    sinks.get(1).getDestination());
            assertEquals(DEFAULT_FILTER, sinks.get(1).getFilter());
            assertEquals(REQUIRED_FILTER, sinks.getFirst().getFilter());
            // A sink routing to a log bucket in its own project has no writer identity (logging_config.proto).
            assertEquals("", sinks.getFirst().getWriterIdentity());
            assertEquals(sinks.getFirst(), config.getSink(GetSinkRequest.newBuilder()
                    .setSinkName(parent + "/sinks/_Required").build()));
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
        given().when().get("/v2/" + parent + "/sinks/_Default").then().statusCode(200)
                .body("name", equalTo("_Default")).body("filter", equalTo(DEFAULT_FILTER));
    }

    @Test
    void requiredBucketAndSinkRefuseEveryChange() throws Exception {
        String project = project();
        String parent = "projects/" + project;
        String bucket = parent + "/locations/global/buckets/_Required";
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of("retentionDays", 1))
                .when().patch("/v2/" + bucket + "?updateMask=retentionDays").then().statusCode(400);
        given().when().delete("/v2/" + bucket).then().statusCode(400);
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of("disabled", true))
                .when().patch("/v2/" + parent + "/sinks/_Required?updateMask=disabled").then().statusCode(403);
        given().when().delete("/v2/" + parent + "/sinks/_Default").then().statusCode(403)
                .body("error.message", equalTo("Sink _Default cannot be deleted. Consider disabling instead"));

        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            ConfigServiceV2Grpc.ConfigServiceV2BlockingStub config = ConfigServiceV2Grpc.newBlockingStub(channel)
                    .withDeadlineAfter(10, TimeUnit.SECONDS);
            assertEquals(Status.Code.FAILED_PRECONDITION, assertThrows(StatusRuntimeException.class,
                    () -> config.updateBucket(UpdateBucketRequest.newBuilder().setName(bucket)
                            .setBucket(LogBucket.newBuilder().setDescription("changed"))
                            .setUpdateMask(FieldMask.newBuilder().addPaths("description")).build()))
                    .getStatus().getCode());
            assertEquals(Status.Code.FAILED_PRECONDITION, assertThrows(StatusRuntimeException.class,
                    () -> config.deleteBucket(DeleteBucketRequest.newBuilder()
                            .setName(parent + "/locations/global/buckets/_Default").build())).getStatus().getCode());
            StatusRuntimeException sink = assertThrows(StatusRuntimeException.class,
                    () -> config.deleteSink(DeleteSinkRequest.newBuilder()
                            .setSinkName(parent + "/sinks/_Required").build()));
            assertEquals(Status.Code.PERMISSION_DENIED, sink.getStatus().getCode());
            assertEquals("Sink _Required cannot be deleted", sink.getStatus().getDescription());
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
        given().when().get("/v2/" + bucket).then().statusCode(200).body("retentionDays", equalTo(400));
        given().when().get("/v2/" + parent + "/sinks/_Required").then().statusCode(200)
                .body("filter", equalTo(REQUIRED_FILTER)).body("disabled", equalTo(null));

        // Refused changes are still recorded, with their status.
        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("UpdateBucket", "DeleteBucket", "UpdateSink", "DeleteSink", "UpdateBucket",
                        "DeleteBucket", "DeleteSink"),
                entries.stream().map(entry -> payload(entry).getString("methodName")
                        .substring("google.logging.v2.ConfigServiceV2.".length())).toList());
        assertEquals(List.of(9, 9, 7, 7, 9, 9, 7),
                entries.stream().map(entry -> payload(entry).getInt("status.code")).toList());
        assertEquals(Map.of("project_id", project, "service", "logging.googleapis.com",
                        "method", "google.logging.v2.ConfigServiceV2.UpdateBucket"),
                new JsonPath(toJson(entries.getFirst())).getMap("resource.labels"));
        assertEquals("audited_resource", new JsonPath(toJson(entries.getFirst())).getString("resource.type"));
    }

    @Test
    void defaultBucketRetentionAndSinkChangesAreKeptAndAudited() throws Exception {
        String project = project();
        String parent = "projects/" + project;
        String bucket = parent + "/locations/global/buckets/_Default";
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of("retentionDays", 1))
                .when().patch("/v2/" + bucket + "?updateMask=retentionDays").then().statusCode(200)
                .body("retentionDays", equalTo(1)).body("name", equalTo(bucket));
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of("retentionDays", 3651))
                .when().patch("/v2/" + bucket + "?updateMask=retentionDays").then().statusCode(400);
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of("retentionDays", 7))
                .when().patch("/v2/" + bucket).then().statusCode(400);
        given().when().get("/v2/" + bucket).then().statusCode(200).body("retentionDays", equalTo(1));

        String sinkName = parent + "/sinks/_Default";
        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            ConfigServiceV2Grpc.ConfigServiceV2BlockingStub config = ConfigServiceV2Grpc.newBlockingStub(channel)
                    .withDeadlineAfter(10, TimeUnit.SECONDS);
            LogExclusion exclusion = LogExclusion.newBuilder().setName("no-data-access")
                    .setFilter("LOG_ID(\"cloudaudit.googleapis.com/data_access\")").build();
            LogSink changed = config.updateSink(UpdateSinkRequest.newBuilder().setSinkName(sinkName)
                    .setSink(LogSink.newBuilder().setName("_Default").setFilter("severity>=ERROR")
                            .addExclusions(exclusion).setDisabled(true))
                    .setUpdateMask(FieldMask.newBuilder().addPaths("filter").addPaths("exclusions")
                            .addPaths("disabled")).build());
            assertEquals("severity>=ERROR", changed.getFilter());
            assertEquals(List.of(exclusion), changed.getExclusionsList());
            assertTrue(changed.getDisabled());
            assertEquals("logging.googleapis.com/" + bucket, changed.getDestination());
            assertEquals(changed, config.getSink(GetSinkRequest.newBuilder().setSinkName(sinkName).build()));
            assertEquals(Status.Code.UNIMPLEMENTED, assertThrows(StatusRuntimeException.class,
                    () -> config.updateSink(UpdateSinkRequest.newBuilder().setSinkName(sinkName)
                            .setSink(LogSink.newBuilder().setDestination("storage.googleapis.com/elsewhere"))
                            .setUpdateMask(FieldMask.newBuilder().addPaths("destination")).build()))
                    .getStatus().getCode());
            assertEquals(changed, config.getSink(GetSinkRequest.newBuilder().setSinkName(sinkName).build()));
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of("disabled", false))
                .when().patch("/v2/" + sinkName + "?updateMask=disabled").then().statusCode(200)
                .body("disabled", equalTo(null)).body("filter", equalTo("severity>=ERROR"));

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("UpdateBucket", "UpdateBucket", "UpdateBucket", "UpdateSink", "UpdateSink",
                        "UpdateSink"),
                entries.stream().map(entry -> payload(entry).getString("methodName")
                        .substring("google.logging.v2.ConfigServiceV2.".length())).toList());
        JsonPath retention = payload(entries.getFirst());
        assertEquals("logging.googleapis.com", retention.getString("serviceName"));
        assertEquals(bucket, retention.getString("resourceName"));
        assertEquals("logging.buckets.update", retention.getString("authorizationInfo[0].permission"));
        assertEquals(bucket, retention.getString("authorizationInfo[0].resource"));
        assertEquals("type.googleapis.com/google.logging.v2.UpdateBucketRequest", retention.getString("request.'@type'"));
        assertEquals(bucket, retention.getString("request.name"));
        assertEquals("retentionDays", retention.getString("request.updateMask"));
        assertEquals(1.0, retention.getDouble("request.bucket.retentionDays"));
        assertEquals(3, payload(entries.get(1)).getInt("status.code"));
        JsonPath sink = payload(entries.get(3));
        assertEquals(sinkName, sink.getString("resourceName"));
        assertEquals("filter,exclusions,disabled", sink.getString("request.updateMask"));
        assertEquals(true, sink.getBoolean("request.sink.disabled"));
        assertEquals(Map.of("project_id", project, "destination", "", "name", "_Default"),
                new JsonPath(toJson(entries.get(3))).getMap("resource.labels"));
        assertEquals(12, payload(entries.get(4)).getInt("status.code"));
        assertEquals("disabled", payload(entries.get(5)).getString("request.updateMask"));
    }
}
