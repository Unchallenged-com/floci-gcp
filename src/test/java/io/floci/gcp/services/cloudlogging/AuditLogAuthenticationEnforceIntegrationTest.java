package io.floci.gcp.services.cloudlogging;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.gcp.testing.IamEnforceProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
@TestProfile(IamEnforceProfile.class)
class AuditLogAuthenticationEnforceIntegrationTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void entriesNameTheKeyAndTheImpersonatorBehindAToken() throws Exception {
        String project = project();
        String accounts = "/v1/projects/" + project + "/serviceAccounts";
        String deployer = createAccount(accounts, "deployer", project);
        String runner = createAccount(accounts, "runner", project);
        String keyFile = given().contentType("application/json").body(Map.of())
                .when().post(accounts + "/" + deployer + "/keys").then().statusCode(200)
                .extract().path("privateKeyData");
        JsonNode key = JSON.readTree(Base64.getDecoder().decode(keyFile));
        String deployerToken = exchange(deployer, key);
        given().urlEncodingEnabled(false).contentType("application/json")
                .body(Map.of("policy", Map.of("bindings", List.of(Map.of("role", "roles/iam.serviceAccountTokenCreator",
                        "members", List.of("serviceAccount:" + deployer))))))
                .when().post(accounts + "/" + runner + ":setIamPolicy").then().statusCode(200);
        String runnerToken = given().urlEncodingEnabled(false).header("Authorization", "Bearer " + deployerToken)
                .contentType("application/json").body(Map.of("scope", List.of("https://www.googleapis.com/auth/cloud-platform")))
                .when().post("/v1/projects/-/serviceAccounts/" + runner + ":generateAccessToken")
                .then().statusCode(200).extract().path("accessToken");

        given().header("Authorization", "Bearer " + deployerToken).contentType("application/json")
                .body(Map.of("accountId", "with-key")).when().post(accounts).then().statusCode(403);
        given().header("Authorization", "Bearer " + runnerToken).contentType("application/json")
                .body(Map.of("accountId", "impersonated")).when().post(accounts).then().statusCode(403);

        List<JsonPath> calls = activity(project).stream().map(AuditLogIntegrationTest::payload)
                .filter(audit -> Integer.valueOf(7).equals(audit.get("status.code"))).toList();
        assertEquals(2, calls.size());
        assertEquals(deployer, calls.getFirst().getString("authenticationInfo.principalEmail"));
        assertEquals("//iam.googleapis.com/projects/" + project + "/serviceAccounts/" + deployer + "/keys/"
                + key.path("private_key_id").asText(), calls.getFirst().getString("authenticationInfo.serviceAccountKeyName"));
        assertEquals(runner, calls.get(1).getString("authenticationInfo.principalEmail"));
        assertEquals(List.of(Map.of("firstPartyPrincipal", Map.of("principalEmail", deployer))),
                calls.get(1).getList("authenticationInfo.serviceAccountDelegationInfo"));
    }

    private static String createAccount(String accounts, String accountId, String project) {
        given().contentType("application/json").body(Map.of("accountId", accountId))
                .when().post(accounts).then().statusCode(200);
        return accountId + "@" + project + ".iam.gserviceaccount.com";
    }

    private static String exchange(String email, JsonNode key) throws Exception {
        long now = Instant.now().getEpochSecond();
        String header = encode(Map.of("alg", "RS256", "typ", "JWT", "kid", key.path("private_key_id").asText()));
        String claims = encode(Map.of("iss", email, "aud", "https://oauth2.googleapis.com/token", "iat", now,
                "exp", now + 600, "scope", "https://www.googleapis.com/auth/cloud-platform"));
        String pem = key.path("private_key").asText().replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        PrivateKey privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update((header + "." + claims).getBytes(StandardCharsets.US_ASCII));
        String assertion = header + "." + claims + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        return given().formParam("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                .formParam("assertion", assertion).when().post("/token")
                .then().statusCode(200).extract().path("access_token");
    }

    private static String encode(Map<String, Object> value) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(JSON.writeValueAsBytes(value));
    }
}
