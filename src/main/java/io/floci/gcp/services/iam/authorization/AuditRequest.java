package io.floci.gcp.services.iam.authorization;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Map;

/**
 * The request an {@link AuditedMethod} is described from: the REST verb or gRPC method, the request
 * body or gRPC message as JSON (lowerCamelCase), and the REST query parameters (empty over gRPC).
 */
public record AuditRequest(String transportMethod, JsonNode body, Map<String, String> query, boolean grpc) {
}
