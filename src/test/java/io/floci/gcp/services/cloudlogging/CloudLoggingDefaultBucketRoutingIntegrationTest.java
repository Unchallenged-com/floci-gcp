package io.floci.gcp.services.cloudlogging;

import io.floci.gcp.services.pubsub.PubSubService;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class CloudLoggingDefaultBucketRoutingIntegrationTest {

    private static final String DEFAULT_FILTER = "NOT LOG_ID(\"cloudaudit.googleapis.com/activity\") AND "
            + "NOT LOG_ID(\"externalaudit.googleapis.com/activity\") AND "
            + "NOT LOG_ID(\"cloudaudit.googleapis.com/system_event\") AND "
            + "NOT LOG_ID(\"externalaudit.googleapis.com/system_event\") AND "
            + "NOT LOG_ID(\"cloudaudit.googleapis.com/access_transparency\") AND "
            + "NOT LOG_ID(\"externalaudit.googleapis.com/access_transparency\")";

    @Inject
    PubSubService pubsub;

    @Test
    void defaultSinkFilterAndExclusionsDecideWhatTheDefaultBucketStores() {
        String project = project();
        write(project, "app", entry("INFO", "before", null));
        patchDefaultSink(project, "filter,exclusions", Map.of(
                "filter", DEFAULT_FILTER + " AND severity>=WARNING",
                "exclusions", List.of(
                        Map.of("name", "noisy", "filter", "LOG_ID(\"noisy\")"),
                        Map.of("name", "inactive", "filter", "LOG_ID(\"app\")", "disabled", true))));

        write(project, "app", entry("INFO", "rejected", null), entry("ERROR", "kept", null));
        write(project, "noisy", entry("ERROR", "excluded", null));

        // Sinks route only the entries received after a change: "before" stays.
        assertEquals(List.of("before", "kept"), texts(project, "app"));
        assertEquals(List.of(), texts(project, "noisy"));
        // The _Required sink still stores the Admin Activity entry of the change.
        assertEquals(List.of("google.logging.v2.ConfigServiceV2.UpdateSink"),
                activity(project).stream().map(e -> payload(e).getString("methodName")).toList());

        // A filter the emulator cannot evaluate is refused rather than silently storing nothing.
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("exclusions", List.of(Map.of("name", "sampled", "filter", "sample(insertId, 0.5)"))))
                .when().patch("/v2/projects/" + project + "/sinks/_Default?updateMask=exclusions")
                .then().statusCode(400);
        write(project, "app", entry("ERROR", "still-kept", null));
        assertEquals(List.of("before", "kept", "still-kept"), texts(project, "app"));
    }

    @Test
    void entriesReceivedWhileTheDefaultSinkIsDisabledAreNotStored() {
        String project = project();
        write(project, "app", entry("INFO", "before", null));
        patchDefaultSink(project, "disabled", Map.of("disabled", true));
        write(project, "app", entry("INFO", "while-disabled", null));
        patchDefaultSink(project, "disabled", Map.of("disabled", false));
        write(project, "app", entry("INFO", "after", null));

        assertEquals(List.of("before", "after"), texts(project, "app"));
        assertEquals(2, activity(project).size());
    }

    @Test
    void entriesOlderThanTheDefaultBucketRetentionAreNotListed() {
        String project = project();
        Instant now = Instant.now();
        write(project, "app",
                entry("INFO", "past-retention", now.minus(40, ChronoUnit.DAYS)),
                entry("INFO", "ten-days", now.minus(10, ChronoUnit.DAYS)),
                entry("INFO", "two-days", now.minus(2, ChronoUnit.DAYS)));
        // An entry older than the 30-day default retention is discarded when it is received.
        assertEquals(List.of("ten-days", "two-days"), texts(project, "app"));

        patchRetention(project, 1);
        assertEquals(List.of(), texts(project, "app"));
        assertEquals(1, activity(project).size(), "_Required keeps its own 400-day retention");

        // Within the grace period of a shortened retention, extending it restores the expired entries.
        patchRetention(project, 30);
        assertEquals(List.of("ten-days", "two-days"), texts(project, "app"));
        // Extending the retention is not retroactive.
        patchRetention(project, 60);
        assertEquals(List.of("ten-days", "two-days"), texts(project, "app"));
    }

    @Test
    void entriesMoreThanADayAheadAreNotListedButAreExported() {
        String project = project();
        String topic = "projects/" + project + "/topics/export";
        String subscription = "projects/" + project + "/subscriptions/export";
        pubsub.createTopic(topic);
        pubsub.createSubscription(subscription, topic, 10);
        given().queryParam("uniqueWriterIdentity", true).contentType("application/json")
                .body(Map.of("name", "export", "destination", "pubsub.googleapis.com/" + topic,
                        "filter", "LOG_ID(\"app\")"))
                .post("/v2/projects/" + project + "/sinks").then().statusCode(200);
        Instant now = Instant.now();
        try {
            write(project, "app",
                    entry("INFO", "now", null),
                    entry("INFO", "within-a-day", now.plus(23, ChronoUnit.HOURS)),
                    entry("INFO", "two-days-ahead", now.plus(2, ChronoUnit.DAYS)));

            assertEquals(List.of("now", "within-a-day"), texts(project, "app"));
            assertEquals(List.of("now", "two-days-ahead", "within-a-day"),
                    pubsub.pull(subscription, 10).stream()
                            .map(message -> new JsonPath(message.getMessage().getData().toStringUtf8())
                                    .getString("textPayload"))
                            .sorted().toList());
        } finally {
            given().delete("/v2/projects/" + project + "/sinks/export").then().statusCode(200);
            pubsub.deleteSubscription(subscription);
            pubsub.deleteTopic(topic);
        }
    }

    private static Map<String, Object> entry(String severity, String text, Instant timestamp) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("severity", severity);
        entry.put("textPayload", text);
        if (timestamp != null) {
            entry.put("timestamp", timestamp.toString());
        }
        return entry;
    }

    @SafeVarargs
    private static void write(String project, String logId, Map<String, Object>... entries) {
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("logName", "projects/" + project + "/logs/" + logId,
                        "resource", Map.of("type", "global"), "entries", List.of(entries)))
                .when().post("/v2/entries:write").then().statusCode(200);
    }

    private static List<String> texts(String project, String logId) {
        List<Map<String, Object>> entries = given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of("projects/" + project),
                        "filter", "LOG_ID(\"" + logId + "\")"))
                .when().post("/v2/entries:list").then().statusCode(200).extract().jsonPath().getList("entries");
        List<String> texts = new ArrayList<>();
        if (entries != null) {
            entries.forEach(entry -> texts.add((String) entry.get("textPayload")));
        }
        return texts;
    }

    private static void patchDefaultSink(String project, String updateMask, Map<String, Object> body) {
        given().urlEncodingEnabled(false).contentType("application/json").body(body)
                .when().patch("/v2/projects/" + project + "/sinks/_Default?updateMask=" + updateMask)
                .then().statusCode(200);
    }

    private static void patchRetention(String project, int days) {
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of("retentionDays", days))
                .when().patch("/v2/projects/" + project + "/locations/global/buckets/_Default?updateMask=retentionDays")
                .then().statusCode(200);
    }
}
