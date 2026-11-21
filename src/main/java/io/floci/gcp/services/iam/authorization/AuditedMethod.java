package io.floci.gcp.services.iam.authorization;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * How one call is recorded in Cloud Audit Logs: the audited service and method, the resource the
 * entry names, its monitored resource, and the request as the entry shows it (with its {@code @type}).
 *
 * @param logParent the resource that owns the audit log, such as {@code projects/my-project}
 * @param policyResource the IAM policy a SetIamPolicy call changes, or null; its policy before and
 *        after the call gives the entry's {@code policyDelta} and {@code response}
 */
public record AuditedMethod(String serviceName, String methodName, String resourceName, String logParent,
        String resourceType, Map<String, String> resourceLabels, Map<String, Object> request,
        String policyResource) {

    private static final ObjectMapper JSON = new ObjectMapper();

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
