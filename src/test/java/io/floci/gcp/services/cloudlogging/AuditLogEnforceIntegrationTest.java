package io.floci.gcp.services.cloudlogging;

import com.google.logging.v2.ConfigServiceV2Grpc;
import com.google.logging.v2.CreateSinkRequest;
import com.google.logging.v2.LogSink;
import io.floci.gcp.services.credentials.CredentialTokenService;
import io.floci.gcp.testing.IamEnforceProfile;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.activity;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.payload;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.project;
import static io.floci.gcp.services.cloudlogging.AuditLogIntegrationTest.toJson;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(IamEnforceProfile.class)
class AuditLogEnforceIntegrationTest {

    @Inject
    CredentialTokenService tokens;
    @TestHTTPResource
    URI endpoint;

    @Test
    void writesRefusedByIamAreRecordedAsDenied() throws Exception {
        String project = project();
        String caller = "intruder@" + project + ".iam.gserviceaccount.com";
        String token = tokens.mintImpersonatedToken(caller, Instant.now().plusSeconds(300)).getTokenValue();

        given().header("Authorization", "Bearer " + token).contentType("application/json")
                .body(Map.of("accountId", "backdoor"))
                .when().post("/v1/projects/" + project + "/serviceAccounts").then().statusCode(403);

        ManagedChannel channel = ManagedChannelBuilder.forAddress(endpoint.getHost(), endpoint.getPort())
                .usePlaintext().build();
        try {
            Metadata headers = new Metadata();
            headers.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + token);
            StatusRuntimeException denied = assertThrows(StatusRuntimeException.class, () ->
                    ConfigServiceV2Grpc.newBlockingStub(channel)
                            .withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers))
                            .withDeadlineAfter(10, TimeUnit.SECONDS)
                            .createSink(CreateSinkRequest.newBuilder().setParent("projects/" + project)
                                    .setSink(LogSink.newBuilder().setName("exfil")
                                            .setDestination("storage.googleapis.com/elsewhere")).build()));
            assertEquals(Status.Code.PERMISSION_DENIED, denied.getStatus().getCode());
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("google.iam.admin.v1.CreateServiceAccount", "google.logging.v2.ConfigServiceV2.CreateSink"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());
        for (Map<String, Object> entry : entries) {
            JsonPath audit = payload(entry);
            assertEquals(7, audit.getInt("status.code"));
            // proto3 JSON leaves out a false granted, as one real denied entry does.
            assertFalse(Boolean.TRUE.equals(audit.get("authorizationInfo[0].granted")));
            assertEquals(caller, audit.getString("authenticationInfo.principalEmail"));
            assertEquals("ERROR", new JsonPath(toJson(entry)).getString("severity"));
        }
    }
}
