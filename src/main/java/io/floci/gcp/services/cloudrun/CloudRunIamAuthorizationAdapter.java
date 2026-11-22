package io.floci.gcp.services.cloudrun;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.cloud.audit.AuthorizationInfo.PermissionType;
import io.floci.gcp.services.iam.IamResource;
import io.floci.gcp.services.iam.authorization.AuditRequest;
import io.floci.gcp.services.iam.authorization.AuditedMethod;
import io.floci.gcp.services.iam.authorization.IamAuthorizationAdapter;
import io.floci.gcp.services.iam.authorization.IamOperation;
import io.floci.gcp.services.iam.authorization.IamPermissionCheck;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@ApplicationScoped
public class CloudRunIamAuthorizationAdapter implements IamAuthorizationAdapter {
    private static final String SERVICE = "run.googleapis.com";
    private static final String LOCATION_PATTERN = "projects/[^/]+/locations/[^/]+";
    private static final String SERVICE_PATTERN = LOCATION_PATTERN + "/services/[^/]+";
    private static final String REVISION_PATTERN = SERVICE_PATTERN + "/revisions/[^/]+";
    private static final Set<String> VIEWER = Set.of("run.services.get", "run.services.list",
            "run.services.getIamPolicy", "run.revisions.get", "run.revisions.list");
    private static final Set<String> DEVELOPER = Set.of("run.services.create", "run.services.get",
            "run.services.list", "run.services.update", "run.services.delete",
            "run.services.getIamPolicy", "run.revisions.get", "run.revisions.list", "run.revisions.delete");
    private static final Set<String> ADMIN = Set.of("run.services.create", "run.services.get",
            "run.services.list", "run.services.update", "run.services.delete",
            "run.services.getIamPolicy", "run.services.setIamPolicy",
            "run.revisions.get", "run.revisions.list", "run.revisions.delete");

    @Override
    public String serviceName() {
        return "cloudrun";
    }

    @Override
    public Set<Class<?>> restControllers() {
        return Set.of(CloudRunController.class);
    }

    @Override
    public Set<String> grpcServices() {
        return Set.of();
    }

    @Override
    public IamOperation restOperation(String method, Map<String, String> path, JsonNode body) {
        String parent = "projects/" + path.get("project") + "/locations/" + path.get("location");
        String resource = switch (method) {
            case "createService", "listServices" -> parent;
            case "getService", "updateService", "deleteService", "getIamPolicy", "setIamPolicy",
                    "testIamPermissions", "listRevisions" -> parent + "/services/" + path.get("serviceId");
            case "getRevision", "deleteRevision" -> parent + "/services/" + path.get("serviceId")
                    + "/revisions/" + path.get("revisionId");
            default -> throw unsupported("REST operation " + method);
        };
        return new IamOperation(Character.toUpperCase(method.charAt(0)) + method.substring(1), resource);
    }

    @Override
    public IamOperation grpcOperation(String method, JsonNode request) {
        throw unsupported("gRPC operation " + method);
    }

    /**
     * Service changes, IAM policy changes and revision deletion, Admin Activity methods of
     * https://docs.cloud.google.com/run/docs/audit-logging ({@code google.cloud.run.v2.Services.*},
     * {@code google.cloud.run.v2.Revisions.DeleteRevision}), on a {@code cloud_run_revision} resource, the Cloud
     * Run type of the resource list that names a service ({@code project_id}, {@code service_name},
     * {@code revision_name}, {@code location}).
     */
    @Override
    public Optional<AuditedMethod> auditedMethod(IamOperation operation, AuditRequest request) {
        String interfaceName = switch (operation.name()) {
            case "CreateService", "UpdateService", "DeleteService", "SetIamPolicy" -> "Services";
            case "DeleteRevision" -> "Revisions";
            default -> null;
        };
        if (interfaceName == null) {
            return Optional.empty();
        }
        String name = "CreateService".equals(operation.name())
                ? operation.resource() + "/services/" + request.query().getOrDefault("serviceId", "")
                : operation.resource();
        String[] parts = name.split("/");
        if (parts.length < 6) {
            return Optional.empty();
        }
        Map<String, Object> audited = AuditedMethod.request(
                "google.cloud.run.v2." + operation.name() + "Request", null);
        switch (operation.name()) {
            case "CreateService" -> {
                audited.put("parent", operation.resource());
                audited.put("serviceId", request.query().getOrDefault("serviceId", ""));
                audited.put("service", AuditedMethod.value(request.body()));
            }
            case "UpdateService" -> audited.put("service", AuditedMethod.value(request.body()));
            case "SetIamPolicy" -> {
                audited.put("resource", name);
                audited.put("policy", AuditedMethod.value(request.body().path("policy")));
            }
            default -> audited.put("name", name);
        }
        Map<String, String> labels = new LinkedHashMap<>();
        labels.put("project_id", parts[1]);
        labels.put("service_name", parts[5]);
        labels.put("revision_name", parts.length > 7 ? parts[7] : "");
        labels.put("location", parts[3]);
        return Optional.of(new AuditedMethod("run.googleapis.com",
                "google.cloud.run.v2." + interfaceName + "." + operation.name(), name, "projects/" + parts[1],
                "cloud_run_revision", labels, audited, "SetIamPolicy".equals(operation.name()) ? name : null,
                PermissionType.ADMIN_WRITE));
    }

    @Override
    public List<IamPermissionCheck> checks(IamOperation operation) {
        String permission = switch (operation.name()) {
            case "CreateService" -> "run.services.create";
            case "ListServices" -> "run.services.list";
            case "GetService" -> "run.services.get";
            case "UpdateService" -> "run.services.update";
            case "DeleteService" -> "run.services.delete";
            case "GetIamPolicy" -> "run.services.getIamPolicy";
            case "SetIamPolicy" -> "run.services.setIamPolicy";
            case "ListRevisions" -> "run.revisions.list";
            case "GetRevision" -> "run.revisions.get";
            case "DeleteRevision" -> "run.revisions.delete";
            case "TestIamPermissions" -> null;
            default -> throw unsupported("operation " + operation.name());
        };
        if (permission == null) {
            return List.of();
        }
        IamResource target = switch (operation.name()) {
            case "CreateService", "ListServices" -> IamResource.projectChild(SERVICE, "Location",
                    operation.resource(), IamResource.projectName(operation.resource()));
            case "ListRevisions" -> operation.resource().endsWith("/services/-")
                    ? IamResource.projectChild(SERVICE, "Location",
                            operation.resource().substring(0, operation.resource().length() - "/services/-".length()),
                            IamResource.projectName(operation.resource()))
                    : requireResource(operation.resource());
            case "GetRevision", "DeleteRevision" -> revisionResource(operation.resource());
            default -> requireResource(operation.resource());
        };
        return List.of(new IamPermissionCheck(permission, target));
    }

    @Override
    public Optional<IamResource> resource(String name) {
        if (name.matches(SERVICE_PATTERN)) {
            return Optional.of(IamResource.projectChild(SERVICE, "Service", name, name));
        }
        return Optional.empty();
    }

    private IamResource revisionResource(String name) {
        if (!name.matches(REVISION_PATTERN)) {
            throw unsupported("resource " + name);
        }
        String service = name.substring(0, name.indexOf("/revisions/"));
        return IamResource.projectChild(SERVICE, "Revision", name, service);
    }

    @Override
    public Map<String, Set<String>> roles() {
        return Map.of("roles/run.viewer", VIEWER, "roles/run.developer", DEVELOPER,
                "roles/run.admin", ADMIN);
    }

    @Override
    public Map<String, Set<String>> basicRoles() {
        return Map.of("roles/viewer", VIEWER, "roles/editor", DEVELOPER, "roles/owner", ADMIN);
    }
}
