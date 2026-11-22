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
import static org.junit.jupiter.api.Assertions.assertNull;

@QuarkusTest
class AuditLogRolesProjectsIntegrationTest {

    @Test
    void customRoleChangesWriteAdminActivityEntries() {
        String project = project();
        String roles = "/v1/projects/" + project + "/roles";
        String role = "projects/" + project + "/roles/backdoor";
        given().contentType("application/json")
                .body(Map.of("roleId", "backdoor", "role", Map.of("title", "Backdoor",
                        "includedPermissions", List.of("iam.serviceAccountKeys.create"))))
                .when().post(roles).then().statusCode(200);
        given().contentType("application/json").body(Map.of("title", "Renamed"))
                .when().patch(roles + "/backdoor?updateMask=title").then().statusCode(200);
        given().when().delete(roles + "/backdoor").then().statusCode(200);
        given().urlEncodingEnabled(false).contentType("application/json").body(Map.of())
                .when().post(roles + "/backdoor:undelete").then().statusCode(200);

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("google.iam.admin.v1.CreateRole", "google.iam.admin.v1.UpdateRole",
                "google.iam.admin.v1.DeleteRole", "google.iam.admin.v1.UndeleteRole"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());
        JsonPath created = payload(entries.getFirst());
        assertEquals(role, created.getString("resourceName"));
        assertEquals("iam.roles.create", created.getString("authorizationInfo[0].permission"));
        assertEquals("backdoor", created.getString("request.role_id"));
        assertEquals("projects/" + project, created.getString("request.parent"));
        assertEquals(List.of("iam.serviceAccountKeys.create"), created.getList("request.role.included_permissions"));
        JsonPath createdEntry = new JsonPath(toJson(entries.getFirst()));
        assertEquals("iam_role", createdEntry.getString("resource.type"));
        assertEquals(Map.of("project_id", project, "role_name", role), createdEntry.getMap("resource.labels"));
        assertEquals(role, payload(entries.get(2)).getString("request.name"));
    }

    @Test
    void projectCreationAndDeletionWriteAdminActivityEntries() {
        String project = project();
        given().contentType("application/json").body(Map.of("projectId", project, "name", "Audit project"))
                .when().post("/v1/projects").then().statusCode(200);
        given().when().delete("/v1/projects/" + project).then().statusCode(200);

        List<Map<String, Object>> entries = activity(project);
        assertEquals(List.of("CreateProject", "DeleteProject"),
                entries.stream().map(entry -> payload(entry).getString("methodName")).toList());
        JsonPath created = payload(entries.getFirst());
        assertEquals("cloudresourcemanager.googleapis.com", created.getString("serviceName"));
        assertEquals("projects/" + project, created.getString("resourceName"));
        assertEquals("type.googleapis.com/google.cloudresourcemanager.v1.CreateProjectRequest",
                created.getString("request.'@type'"));
        assertEquals(project, created.getString("request.project.projectId"));
        assertEquals(Map.of(), created.getMap("authorizationInfo[0].resourceAttributes"));
        assertNull(created.get("authorizationInfo[0].permissionType"));
        assertEquals("project", new JsonPath(toJson(entries.getFirst())).getString("resource.type"));
    }
}
