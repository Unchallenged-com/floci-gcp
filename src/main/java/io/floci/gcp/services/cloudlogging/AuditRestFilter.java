package io.floci.gcp.services.cloudlogging;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.rpc.Code;
import io.floci.gcp.core.common.RequestBody;
import io.floci.gcp.services.iam.authorization.AuditRequest;
import io.floci.gcp.services.iam.authorization.IamAuthorizationAdapter;
import io.floci.gcp.services.iam.authorization.IamAuthorizationRegistry;
import io.floci.gcp.services.iam.authorization.IamOperation;
import io.vertx.core.http.HttpServerRequest;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Records the REST calls that write audit entries. It runs before IAM authorization, so
 * a call that authorization refuses is recorded with its PERMISSION_DENIED status.
 */
@Provider
@Priority(Priorities.AUTHORIZATION - 2)
@ApplicationScoped
public class AuditRestFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Logger LOG = Logger.getLogger(AuditRestFilter.class);
    private static final String PROPERTY = AuditRestFilter.class.getName();

    @Context
    ResourceInfo resourceInfo;

    @Context
    HttpServerRequest httpRequest;

    private final IamAuthorizationRegistry registry;
    private final AuditLogRecorder recorder;
    private final ObjectMapper mapper;

    @Inject
    public AuditRestFilter(IamAuthorizationRegistry registry, AuditLogRecorder recorder, ObjectMapper mapper) {
        this.registry = registry;
        this.recorder = recorder;
        this.mapper = mapper;
    }

    @Override
    public void filter(ContainerRequestContext context) throws IOException {
        if (resourceInfo == null || resourceInfo.getResourceClass() == null) {
            return;
        }
        Optional<IamAuthorizationAdapter> adapter = registry.rest(resourceInfo.getResourceClass());
        if (adapter.isEmpty()) {
            return;
        }
        JsonNode body = mapper.createObjectNode();
        byte[] bytes = RequestBody.of(context);
        if (bytes.length > 0) {
            try {
                body = mapper.readTree(bytes);
            } catch (IOException e) {
                // The handler answers the malformed body; the call is not audited.
                return;
            }
        }
        Map<String, String> path = new LinkedHashMap<>();
        context.getUriInfo().getPathParameters().forEach((key, values) -> path.put(key, values.getFirst()));
        Map<String, String> query = new LinkedHashMap<>();
        context.getUriInfo().getQueryParameters().forEach((key, values) -> query.put(key, values.getFirst()));
        IamOperation operation;
        try {
            operation = adapter.get().restOperation(resourceInfo.getResourceMethod().getName(), path, body);
        } catch (RuntimeException e) {
            LOG.debugf(e, "No audit mapping for %s", resourceInfo.getResourceMethod().getName());
            return;
        }
        String callerIp = httpRequest == null || httpRequest.remoteAddress() == null
                ? null : httpRequest.remoteAddress().hostAddress();
        recorder.begin(adapter.get(), operation, new AuditRequest(context.getMethod(), body, query, false),
                        context.getHeaderString(HttpHeaders.AUTHORIZATION), callerIp,
                        context.getHeaderString(HttpHeaders.USER_AGENT))
                .ifPresent(call -> context.setProperty(PROPERTY, call));
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        if (!(request.getProperty(PROPERTY) instanceof AuditLogRecorder.Call call)) {
            return;
        }
        request.removeProperty(PROPERTY);
        int status = response.getStatus();
        if (status >= 200 && status < 300) {
            recorder.complete(call, Code.OK_VALUE, null);
            return;
        }
        JsonNode error = response.hasEntity() ? errorBody(response.getEntity()) : null;
        String message = error == null ? null : error.path("message").asText(null);
        recorder.complete(call, code(error == null ? null : error.path("status").asText(null), status), message);
    }

    private JsonNode errorBody(Object entity) {
        try {
            JsonNode node = entity instanceof String text ? mapper.readTree(text) : mapper.valueToTree(entity);
            return node.has("error") ? node.get("error") : null;
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }

    /** The {@code google.rpc.Code} of a failed call, from its error status or else its HTTP status (AIP-193). */
    static int code(String status, int httpStatus) {
        if (status != null) {
            try {
                return Code.valueOf(status).getNumber();
            } catch (IllegalArgumentException e) {
                // Not a canonical status name: fall back to the HTTP status.
            }
        }
        return switch (httpStatus) {
            case 400 -> Code.INVALID_ARGUMENT_VALUE;
            case 401 -> Code.UNAUTHENTICATED_VALUE;
            case 403 -> Code.PERMISSION_DENIED_VALUE;
            case 404 -> Code.NOT_FOUND_VALUE;
            case 409 -> Code.ABORTED_VALUE;
            case 412 -> Code.FAILED_PRECONDITION_VALUE;
            case 429 -> Code.RESOURCE_EXHAUSTED_VALUE;
            case 501 -> Code.UNIMPLEMENTED_VALUE;
            case 503 -> Code.UNAVAILABLE_VALUE;
            case 504 -> Code.DEADLINE_EXCEEDED_VALUE;
            default -> httpStatus >= 500 ? Code.INTERNAL_VALUE : Code.UNKNOWN_VALUE;
        };
    }
}
