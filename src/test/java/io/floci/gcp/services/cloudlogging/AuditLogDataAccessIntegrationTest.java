package io.floci.gcp.services.cloudlogging;

import com.google.iam.v1.AuditConfig;
import com.google.iam.v1.AuditLogConfig;
import com.google.iam.v1.IAMPolicyGrpc;
import com.google.iam.v1.Policy;
import com.google.iam.v1.SetIamPolicyRequest;
import com.google.protobuf.FieldMask;
import io.floci.gcp.core.common.ProjectRecord;
import io.floci.gcp.core.common.ProjectRegistry;
import io.floci.gcp.services.credentials.CredentialTokenService;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.toJson;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class AuditLogDataAccessIntegrationTest {
    private static final String CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform";

    @Inject
    CredentialTokenService tokens;
    @Inject
    ProjectRegistry projects;
    @TestHTTPResource
    URI endpoint;

    @Test
    void dataAccessEntriesAreWrittenOnlyForTheLogTypesTheProjectEnables() {
        String project = project();
        String email = createAccount(project, "runner");
        String secret = createSecret(project, "db-password");

        mint(email);
        access(secret);
        assertTrue(dataAccess(project).isEmpty(), "Data Access logs are disabled by default");

        enable("/v1/projects/" + project, List.of(Map.of("service", "allServices",
                "auditLogConfigs", List.of(Map.of("logType", "DATA_READ")))));
        mint(email);
        access(secret);
        given().when().get("/v1/" + secret).then().statusCode(200);

        List<Map<String, Object>> entries = dataAccess(project);
        assertEquals(List.of("GenerateAccessToken", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList(),
                "ADMIN_READ (GetSecret) is not enabled");

        JsonPath token = payload(entries.getFirst());
        assertEquals("iamcredentials.googleapis.com", token.getString("serviceName"));
        assertEquals("iam.serviceAccounts.getAccessToken", token.getString("authorizationInfo[0].permission"));
        assertEquals("DATA_READ", token.getString("authorizationInfo[0].permissionType"));
        assertEquals("type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest",
                token.getString("request.'@type'"));
        assertEquals("projects/-/serviceAccounts/" + email, token.getString("request.name"));
        assertEquals(List.of(CLOUD_PLATFORM), token.getList("request.scope"));
        assertTrue(token.getString("resourceName").startsWith("projects/-/serviceAccounts/"));
        JsonPath tokenEntry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("INFO", tokenEntry.getString("severity"));
        assertEquals("projects/" + project + "/logs/cloudaudit.googleapis.com%2Fdata_access", tokenEntry.getString("logName"));
        assertEquals("service_account", tokenEntry.getString("resource.type"));
        assertEquals(email, tokenEntry.getString("resource.labels.email_id"));

        JsonPath read = payload(entries.get(1));
        assertEquals(secret + "/versions/1", read.getString("resourceName"));
        assertEquals("DATA_READ", read.getString("authorizationInfo[0].permissionType"));
        assertEquals(secret + "/versions/1", read.getString("request.name"));
        assertFalse(toJson(entries.get(1)).contains(Base64.getEncoder().encodeToString("hunter2".getBytes())),
                "the secret payload is never logged");
        JsonPath readEntry = new JsonPath(toJson(entries.get(1)));
        assertEquals("audited_resource", readEntry.getString("resource.type"));
        assertEquals(Map.of("method", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
                "project_id", project, "service", "secretmanager.googleapis.com"), readEntry.getMap("resource.labels"));

        enable("/v1/projects/" + project, List.of(Map.of("service", "secretmanager.googleapis.com",
                "auditLogConfigs", List.of(Map.of("logType", "ADMIN_READ")))));
        given().when().get("/v1/" + secret).then().statusCode(200);
        JsonPath getSecret = payload(dataAccess(project).getLast());
        assertEquals("google.cloud.secretmanager.v1.SecretManagerService.GetSecret", getSecret.getString("methodName"));
        assertEquals("ADMIN_READ", getSecret.getString("authorizationInfo[0].permissionType"));
    }

    @Test
    void exemptedMembersAreNotLogged() {
        String project = project();
        String secret = createSecret(project, "api-key");
        String caller = "batch@" + project + ".iam.gserviceaccount.com";
        String exempt = "Bearer " + tokens.mintImpersonatedToken(caller, Instant.now().plusSeconds(300)).getTokenValue();
        enable("/v1/projects/" + project, List.of(Map.of("service", "secretmanager.googleapis.com",
                "auditLogConfigs", List.of(Map.of("logType", "DATA_READ",
                        "exemptedMembers", List.of("serviceAccount:" + caller))))));

        given().urlEncodingEnabled(false).header("Authorization", exempt).when().get("/v1/" + secret + "/versions/1:access")
                .then().statusCode(200);
        access(secret);

        List<Map<String, Object>> entries = dataAccess(project);
        assertEquals(1, entries.size());
        assertEquals(Map.of(), payload(entries.getFirst()).getMap("authenticationInfo"));
    }

    @Test
    void anOrganizationsAuditConfigsApplyToItsProjects() throws Exception {
        String project = project();
        String organization = "organizations/7" + Math.abs(UUID.randomUUID().getLeastSignificantBits() % 100000000L);
        ProjectRecord record = new ProjectRecord();
        record.setProjectId(project);
        record.setParentType("organization");
        record.setParentId(organization.substring("organizations/".length()));
        projects.createOrAdopt(record);
        String secret = createSecret(project, "token");

        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            IAMPolicyGrpc.newBlockingStub(channel).withDeadlineAfter(10, TimeUnit.SECONDS)
                    .setIamPolicy(SetIamPolicyRequest.newBuilder().setResource(organization)
                            .setPolicy(Policy.newBuilder().addAuditConfigs(AuditConfig.newBuilder()
                                    .setService("allServices").addAuditLogConfigs(AuditLogConfig.newBuilder()
                                            .setLogType(AuditLogConfig.LogType.DATA_READ))))
                            .setUpdateMask(FieldMask.newBuilder().addPaths("audit_configs")).build());
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
        access(secret);

        assertEquals(List.of("google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"),
                dataAccess(project).stream().map(entry -> payload(entry).getString("methodName")).toList());
    }

    private static String createAccount(String project, String accountId) {
        given().contentType("application/json").body(Map.of("accountId", accountId))
                .when().post("/v1/projects/" + project + "/serviceAccounts").then().statusCode(200);
        return accountId + "@" + project + ".iam.gserviceaccount.com";
    }

    private static String createSecret(String project, String secretId) {
        String secret = "projects/" + project + "/secrets/" + secretId;
        given().contentType("application/json").body(Map.of("replication", Map.of("automatic", Map.of())))
                .when().post("/v1/projects/" + project + "/secrets?secretId=" + secretId).then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("payload", Map.of("data", Base64.getEncoder().encodeToString("hunter2".getBytes()))))
                .when().post("/v1/" + secret + ":addVersion").then().statusCode(200);
        return secret;
    }

    private static void mint(String email) {
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("scope", List.of(CLOUD_PLATFORM)))
                .when().post("/v1/projects/-/serviceAccounts/" + email + ":generateAccessToken")
                .then().statusCode(200);
    }

    private static void access(String secret) {
        given().urlEncodingEnabled(false).when().get("/v1/" + secret + "/versions/1:access").then().statusCode(200);
    }

    private static void enable(String base, List<Map<String, Object>> auditConfigs) {
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("auditConfigs", auditConfigs), "updateMask", "auditConfigs"))
                .when().post(base + ":setIamPolicy").then().statusCode(200);
    }

    private static List<Map<String, Object>> dataAccess(String project) {
        List<Map<String, Object>> entries = given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("resourceNames", List.of("projects/" + project),
                        "filter", "logName=\"projects/" + project + "/logs/cloudaudit.googleapis.com%2Fdata_access\""))
                .when().post("/v2/entries:list")
                .then().statusCode(200).extract().jsonPath().getList("entries");
        return entries == null ? List.of() : entries;
    }
}
