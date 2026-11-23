package io.floci.gcp.services.cloudlogging;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class CloudLoggingSinkErrorIntegrationTest {

    @Test
    void aSinkToAMissingTopicWritesASinkErrorEntry() {
        String project = "sink-error-" + UUID.randomUUID().toString().substring(0, 8);
        String parent = "projects/" + project;
        String destination = "pubsub.googleapis.com/projects/" + project + "/topics/missing";
        String log = parent + "/logs/app";
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("name", "to-missing", "destination", destination, "filter", "logName=\"" + log + "\""))
                .when().post("/v2/" + parent + "/sinks?uniqueWriterIdentity=true").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("logName", log, "entries", List.of(Map.of("textPayload", "x"))))
                .when().post("/v2/entries:write").then().statusCode(200);

        List<Map<String, Object>> entries = given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of(parent),
                        "filter", "logName=\"" + parent + "/logs/logging.googleapis.com%2Fsink_error\""))
                .when().post("/v2/entries:list").then().statusCode(200).extract().jsonPath().getList("entries");
        assertEquals(1, entries.size());
        JsonPath entry = new JsonPath(new ObjectMapper().valueToTree(entries.getFirst()).toString());
        assertEquals("ERROR", entry.getString("severity"));
        assertEquals("logging_sink", entry.getString("resource.type"));
        assertEquals(Map.of("destination", destination, "name", "to-missing", "project_id", project),
                entry.getMap("resource.labels"));
        assertEquals(Map.of("activity_type_name", "LoggingSinkConfigErrorV2", "destination", destination,
                "error_code", "topic_not_found", "error_detail", "", "sink_id", "to-missing"), entry.getMap("labels"));
        assertEquals("Cloud Logging sink configuration error in " + project + ", sink to-missing: topic_not_found ()",
                entry.getString("textPayload"));
    }
}
