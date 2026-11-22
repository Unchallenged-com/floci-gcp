package io.floci.gcp.services.iam.authorization;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.audit.AuthorizationInfo.PermissionType;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * How one call is recorded in Cloud Audit Logs: the audited service and method, the resource the
 * entry names, its monitored resource, and the request as the entry shows it (with its {@code @type}).
 *
 * @param logParent the resource that owns the audit log, such as {@code projects/my-project}
 * @param policyResource the IAM policy a SetIamPolicy call changes, or null; its policy before and
 *        after the call gives the entry's {@code policyDelta} and {@code response}
 * @param permissionType the type of the permission the method checks: {@code ADMIN_WRITE} methods write
 *        Admin Activity entries, the other types Data Access entries when the policy's auditConfigs enable them
 * @param bareAuthorization true when the entry's {@code authorizationInfo} carries neither a {@code permissionType}
 *        nor resource attributes, as Cloud Storage entries are captured
 * @param resourceLocations the {@code resourceLocation.currentLocations} of the entry, empty for none
 * @param serviceData a fixed {@code serviceData} object (with its {@code @type}) the entry carries, or null
 */
public record AuditedMethod(String serviceName, String methodName, String resourceName, String logParent,
        String resourceType, Map<String, String> resourceLabels, Map<String, Object> request,
        String policyResource, PermissionType permissionType, boolean bareAuthorization,
        List<String> resourceLocations, Map<String, Object> serviceData) {

    private static final ObjectMapper JSON = new ObjectMapper();

    public AuditedMethod(String serviceName, String methodName, String resourceName, String logParent,
            String resourceType, Map<String, String> resourceLabels, Map<String, Object> request,
            String policyResource, PermissionType permissionType, boolean bareAuthorization,
            List<String> resourceLocations) {
        this(serviceName, methodName, resourceName, logParent, resourceType, resourceLabels, request, policyResource,
                permissionType, bareAuthorization, resourceLocations, null);
    }

    public AuditedMethod(String serviceName, String methodName, String resourceName, String logParent,
            String resourceType, Map<String, String> resourceLabels, Map<String, Object> request,
            String policyResource, PermissionType permissionType) {
        this(serviceName, methodName, resourceName, logParent, resourceType, resourceLabels, request, policyResource,
                permissionType, false, List.of());
    }

    /** An Admin Activity method. */
    public AuditedMethod(String serviceName, String methodName, String resourceName, String logParent,
            String resourceType, Map<String, String> resourceLabels, Map<String, Object> request,
            String policyResource) {
        this(serviceName, methodName, resourceName, logParent, resourceType, resourceLabels, request, policyResource,
                PermissionType.ADMIN_WRITE);
    }

    /** A request object typed {@code type.googleapis.com/<protoType>}, starting from the given JSON fields. */
    public static Map<String, Object> request(String protoType, JsonNode fields) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("@type", "type.googleapis.com/" + protoType);
        if (fields != null && fields.isObject()) {
            request.putAll(JSON.convertValue(fields, new TypeReference<Map<String, Object>>() {}));
        }
        return request;
    }

    /** A JSON value as plain Java objects, or null. */
    public static Object value(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() ? null : JSON.convertValue(node, Object.class);
    }
}
