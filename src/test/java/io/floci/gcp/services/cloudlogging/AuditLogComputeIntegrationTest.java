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
class AuditLogComputeIntegrationTest {

    @Test
    void changesWriteFirstAndLastOperationEntries() {
        String project = project();
        String base = "/compute/v1/projects/" + project + "/global";
        given().contentType("application/json").body(Map.of("name", "corp", "autoCreateSubnetworks", false))
                .when().post(base + "/networks").then().statusCode(200);
        given().contentType("application/json").body(Map.of("name", "allow-ssh", "network", "global/networks/corp",
                        "allowed", List.of(Map.of("IPProtocol", "tcp", "ports", List.of("22")))))
                .when().post(base + "/firewalls").then().statusCode(200);
        given().when().delete(base + "/firewalls/allow-ssh").then().statusCode(200);

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("v1.compute.networks.insert", "v1.compute.networks.insert", "v1.compute.firewalls.insert",
                "v1.compute.firewalls.insert", "v1.compute.firewalls.delete", "v1.compute.firewalls.delete"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());

        JsonPath first = new JsonPath(toJson(entries.get(2)));
        JsonPath last = new JsonPath(toJson(entries.get(3)));
        assertEquals("projects/" + project + "/global/firewalls/allow-ssh", first.getString("protoPayload.resourceName"));
        assertEquals("compute.firewalls.create", first.getString("protoPayload.authorizationInfo[0].permission"));
        assertEquals("type.googleapis.com/compute.firewalls.insert", first.getString("protoPayload.request.'@type'"));
        assertEquals("allow-ssh", first.getString("protoPayload.request.name"));
        assertEquals(true, first.getBoolean("operation.first"));
        assertEquals("compute.googleapis.com", first.getString("operation.producer"));
        assertEquals(first.getString("operation.id"), last.getString("operation.id"));
        assertEquals(true, last.getBoolean("operation.last"));
        assertEquals(List.of(), last.getList("protoPayload.authorizationInfo") == null ? List.of()
                : last.getList("protoPayload.authorizationInfo"));
        assertEquals(Map.of("@type", "type.googleapis.com/compute.firewalls.insert"), last.getMap("protoPayload.request"));
        assertEquals("gce_firewall_rule", first.getString("resource.type"));
        assertEquals(project, first.getString("resource.labels.project_id"));
        assertEquals("gce_network", new JsonPath(toJson(entries.getFirst())).getString("resource.type"));
    }
}
