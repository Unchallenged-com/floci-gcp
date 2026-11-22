package io.floci.gcp.services.cloudlogging;

import io.floci.gcp.services.credentials.CredentialTokenService;
import io.floci.gcp.testing.IamEnforceProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
@TestProfile(IamEnforceProfile.class)
class AuditLogReadAccessEnforceIntegrationTest {

    @Inject
    CredentialTokenService tokens;

    @Test
    void entryMethodsAreCheckedAndDataAccessLogsNeedPrivateAccess() {
        String project = project();
        String reader = "reader@" + project + ".iam.gserviceaccount.com";
        String token = "Bearer " + tokens.mintImpersonatedToken(reader, Instant.now().plusSeconds(300)).getTokenValue();

        given().urlEncodingEnabled(false).header("Authorization", token).contentType("application/json")
                .body(Map.of("logName", "projects/" + project + "/logs/app", "entries", List.of(Map.of("textPayload", "x"))))
                .when().post("/v2/entries:write").then().statusCode(403);
        given().urlEncodingEnabled(false).header("Authorization", token).contentType("application/json")
                .body(Map.of("resourceNames", List.of("projects/" + project)))
                .when().post("/v2/entries:list").then().statusCode(403);

        given().contentType("application/json").body(Map.of("replication", Map.of("automatic", Map.of())))
                .when().post("/v1/projects/" + project + "/secrets?secretId=s").then().statusCode(200);
        setPolicy(project, "roles/logging.viewer", reader, true);
        given().urlEncodingEnabled(false).when().get("/v1/projects/" + project + "/secrets/s").then().statusCode(200);

        assertEquals(List.of(), methods(project, token), "Logs Viewer does not see Data Access entries");
        setPolicy(project, "roles/logging.privateLogViewer", reader, false);
        assertEquals(List.of("google.cloud.secretmanager.v1.SecretManagerService.GetSecret"), methods(project, token));
    }

    private static void setPolicy(String project, String role, String member, boolean withAuditConfigs) {
        Map<String, Object> policy = withAuditConfigs
                ? Map.of("bindings", List.of(Map.of("role", role, "members", List.of("serviceAccount:" + member))),
                        "auditConfigs", List.of(Map.of("service", "allServices",
                                "auditLogConfigs", List.of(Map.of("logType", "ADMIN_READ")))))
                : Map.of("bindings", List.of(Map.of("role", role, "members", List.of("serviceAccount:" + member))));
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", policy, "updateMask", withAuditConfigs ? "bindings,etag,auditConfigs" : "bindings,etag"))
                .when().post("/v1/projects/" + project + ":setIamPolicy").then().statusCode(200);
    }

    private static List<String> methods(String project, String token) {
        List<Map<String, Object>> entries = given().urlEncodingEnabled(false).header("Authorization", token)
                .contentType("application/json")
                .body(Map.of("resourceNames", List.of("projects/" + project), "filter",
                        "logName=\"projects/" + project + "/logs/cloudaudit.googleapis.com%2Fdata_access\""))
                .when().post("/v2/entries:list").then().statusCode(200).extract().jsonPath().getList("entries");
        return entries == null ? List.of() : entries.stream().map(entry -> payload(entry).getString("methodName"))
                .filter(method -> !method.endsWith("ListLogEntries")).toList();
    }
}
