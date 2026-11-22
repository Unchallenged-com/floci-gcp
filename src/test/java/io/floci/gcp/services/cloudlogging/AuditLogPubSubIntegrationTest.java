package io.floci.gcp.services.cloudlogging;

import com.google.pubsub.v1.PublisherGrpc;
import com.google.pubsub.v1.Topic;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.toJson;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class AuditLogPubSubIntegrationTest {

    @TestHTTPResource
    URI endpoint;

    @Test
    void topicAndSubscriptionChangesWriteAdminActivityEntries() throws Exception {
        String project = project();
        String base = "/v1/projects/" + project;
        String topic = "projects/" + project + "/topics/events";
        given().contentType("application/json").body(Map.of()).when().put(base + "/topics/events").then().statusCode(200);
        given().contentType("application/json").body(Map.of("topic", topic))
                .when().put(base + "/subscriptions/exfil").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("bindings", List.of(Map.of("role", "roles/pubsub.subscriber",
                        "members", List.of("user:attacker@example.com"))))))
                .when().post(base + "/topics/events:setIamPolicy").then().statusCode(200);
        given().when().delete(base + "/subscriptions/exfil").then().statusCode(200);
        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            PublisherGrpc.newBlockingStub(channel).withDeadlineAfter(10, TimeUnit.SECONDS)
                    .createTopic(Topic.newBuilder().setName("projects/" + project + "/topics/grpc").build());
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("google.pubsub.v1.Publisher.CreateTopic", "google.pubsub.v1.Subscriber.CreateSubscription",
                "google.iam.v1.IAMPolicy.SetIamPolicy", "google.pubsub.v1.Subscriber.DeleteSubscription",
                "google.pubsub.v1.Publisher.CreateTopic"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());
        JsonPath created = payload(entries.getFirst());
        assertEquals("pubsub.googleapis.com", created.getString("serviceName"));
        assertEquals(topic, created.getString("resourceName"));
        assertEquals("type.googleapis.com/google.pubsub.v1.Topic", created.getString("request.'@type'"));
        assertEquals(topic, created.getString("request.name"));
        JsonPath createdEntry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("pubsub_topic", createdEntry.getString("resource.type"));
        assertEquals(Map.of("project_id", project, "topic_id", "events"), createdEntry.getMap("resource.labels"));
        assertEquals("pubsub_subscription", new JsonPath(toJson(entries.get(1))).getString("resource.type"));
        assertEquals(List.of(Map.of("action", "ADD", "role", "roles/pubsub.subscriber", "member", "user:attacker@example.com")),
                payload(entries.get(2)).getList("serviceData.policyDelta.bindingDeltas"));
        assertEquals("projects/" + project + "/topics/grpc", payload(entries.get(4)).getString("request.name"));
    }
}
