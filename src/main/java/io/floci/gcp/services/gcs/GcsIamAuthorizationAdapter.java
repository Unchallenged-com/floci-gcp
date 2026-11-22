package io.floci.gcp.services.gcs;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.cloud.audit.AuthorizationInfo.PermissionType;
import io.floci.gcp.services.gcs.model.GcsBucket;
import io.floci.gcp.services.iam.IamResource;
import io.floci.gcp.services.iam.authorization.AuditedMethod;
import io.floci.gcp.services.iam.authorization.IamAuthorizationAdapter;
import io.floci.gcp.services.iam.authorization.IamIdentityKind;
import io.floci.gcp.services.iam.authorization.IamOperation;
import io.floci.gcp.services.iam.authorization.IamPermissionCheck;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** GCS resource mapping for the shared evaluator. Enforcement remains in the service path. */
@ApplicationScoped
public class GcsIamAuthorizationAdapter implements IamAuthorizationAdapter {

    private static final String STORAGE = "storage.googleapis.com";

    private final Instance<GcsService> services;

    @Inject
    public GcsIamAuthorizationAdapter(Instance<GcsService> services) {
        this.services = services;
    }

    @Override
    public String serviceName() {
        return "gcs";
    }

    @Override
    public Set<Class<?>> restControllers() {
        return Set.of();
    }

    @Override
    public Set<String> grpcServices() {
        return Set.of();
    }

    @Override
    public IamOperation restOperation(String method, Map<String, String> path, JsonNode body) {
        throw unsupported("REST operation " + method);
    }

    @Override
    public IamOperation grpcOperation(String method, JsonNode request) {
        throw unsupported("gRPC operation " + method);
    }

    @Override
    public List<IamPermissionCheck> checks(IamOperation operation) {
        throw unsupported("operation " + operation.name());
    }

    @Override
    public Optional<IamResource> resource(String name) {
        return Optional.empty();
    }

    public IamResource bucketResource(String bucket) {
        return IamResource.gcsBucket(bucket, services.get().bucketProject(bucket));
    }

    public IamResource objectResource(String bucket, String object) {
        return IamResource.gcsObject(bucket, object, services.get().bucketProject(bucket));
    }

    /**
     * The Data Access entry of a Cloud Storage call checked with {@code permission}, or empty when it is not
     * audited. Types follow https://docs.cloud.google.com/storage/docs/audit-logging (updating and deleting
     * buckets and setting their IAM policy are ADMIN_WRITE; getting bucket metadata, listing buckets and getting
     * IAM policies are ADMIN_READ; getting and listing objects DATA_READ; creating
     * and deleting objects DATA_WRITE). Method names, resource names and the {@code gcs_bucket} resource follow
     * captured entries, which carry no {@code permissionType} and empty resource attributes. {@code object} is
     * null for a bucket-level call; a bucket that does not exist is not audited.
     */
    public Optional<AuditedMethod> storageAuditedMethod(String bucket, String object, String permission) {
        PermissionType type = switch (permission) {
            case "storage.objects.get", "storage.objects.list" -> PermissionType.DATA_READ;
            case "storage.objects.create", "storage.objects.delete" -> PermissionType.DATA_WRITE;
            case "storage.buckets.get", "storage.buckets.getIamPolicy" -> PermissionType.ADMIN_READ;
            case "storage.buckets.update", "storage.buckets.delete", "storage.buckets.setIamPolicy" ->
                    PermissionType.ADMIN_WRITE;
            default -> null;
        };
        if (type == null) {
            return Optional.empty();
        }
        GcsBucket meta;
        try {
            meta = services.get().getBucket(bucket);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
        String location = meta.getLocation() == null ? "" : meta.getLocation().toLowerCase(Locale.ROOT);
        String method = switch (permission) {
            case "storage.buckets.getIamPolicy" -> "storage.getIamPermissions";
            case "storage.buckets.setIamPolicy" -> "storage.setIamPermissions";
            default -> permission;
        };
        String name = "projects/_/buckets/" + bucket
                + (object != null && !"storage.objects.list".equals(permission) ? "/objects/" + object : "");
        Map<String, String> labels = new LinkedHashMap<>();
        labels.put("bucket_name", bucket);
        labels.put("location", location);
        labels.put("project_id", meta.getProjectId());
        String policy = "storage.buckets.setIamPolicy".equals(permission) ? IamResource.gcsBucket(bucket).policyResource()
                : null;
        return Optional.of(new AuditedMethod(STORAGE, method, name, "projects/" + meta.getProjectId(), "gcs_bucket",
                labels, null, policy, type, true, location.isEmpty() ? List.of() : List.of(location)));
    }

    /** {@code storage.buckets.create}, recorded before the bucket exists, as captured on a {@code gcs_bucket}. */
    public AuditedMethod bucketCreateAuditedMethod(String project, String bucket, String location) {
        String region = location == null || location.isBlank() ? "us" : location.toLowerCase(Locale.ROOT);
        Map<String, String> labels = new LinkedHashMap<>();
        labels.put("bucket_name", bucket);
        labels.put("location", region);
        labels.put("project_id", project);
        // Captured buckets.create entries (2023-03-09 and 2026-01-04) record the bucket's initial legacy-role
        // grants to the project's owners, editors and viewers, in this order.
        Map<String, Object> serviceData = new LinkedHashMap<>();
        serviceData.put("@type", "type.googleapis.com/google.iam.v1.logging.AuditData");
        serviceData.put("policyDelta", Map.of("bindingDeltas", List.of(
                Map.of("action", "ADD", "role", "roles/storage.legacyBucketOwner", "member", "projectEditor:" + project),
                Map.of("action", "ADD", "role", "roles/storage.legacyBucketOwner", "member", "projectOwner:" + project),
                Map.of("action", "ADD", "role", "roles/storage.legacyBucketReader", "member", "projectViewer:" + project))));
        return new AuditedMethod(STORAGE, "storage.buckets.create", "projects/_/buckets/" + bucket,
                "projects/" + project, "gcs_bucket", labels, null, null, PermissionType.ADMIN_WRITE, true,
                List.of(region), serviceData);
    }

    /** {@code storage.buckets.list} in a project, as captured: resource {@code projects/_/buckets/*}. */
    public AuditedMethod bucketListAuditedMethod(String project) {
        return new AuditedMethod(STORAGE, "storage.buckets.list", "projects/_/buckets/*", "projects/" + project,
                "gcs_bucket", Map.of("project_id", project), null, null, PermissionType.ADMIN_READ, true, List.of());
    }

    @Override
    public Map<String, Set<String>> roles() {
        return Map.of();
    }

    @Override
    public boolean requiresPolicyEvaluation(IamIdentityKind identityKind) {
        return true;
    }

}
