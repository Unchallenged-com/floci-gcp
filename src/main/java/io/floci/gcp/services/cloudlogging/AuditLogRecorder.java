package io.floci.gcp.services.cloudlogging;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.cloud.audit.AuditLog;
import com.google.cloud.audit.AuthenticationInfo;
import com.google.cloud.audit.AuthorizationInfo;
import com.google.cloud.audit.RequestMetadata;
import com.google.cloud.audit.ResourceLocation;
import com.google.iam.v1.BindingDelta;
import com.google.iam.v1.PolicyDelta;
import com.google.iam.v1.logging.AuditData;
import com.google.protobuf.Any;
import com.google.protobuf.Struct;
import com.google.protobuf.Timestamp;
import com.google.rpc.Code;
import com.google.rpc.Status;
import com.google.rpc.context.AttributeContext;
import com.google.type.Expr;
import io.floci.gcp.services.cloudlogging.model.StoredLogEntry;
import io.floci.gcp.services.iam.IamPrincipal;
import io.floci.gcp.services.iam.IamPrincipalResolver;
import io.floci.gcp.services.iam.IamResource;
import io.floci.gcp.services.iam.IamResourceHierarchy;
import io.floci.gcp.services.iam.IamService;
import io.floci.gcp.services.iam.authorization.AuditRequest;
import io.floci.gcp.services.iam.authorization.AuditTrail;
import io.floci.gcp.services.iam.authorization.AuditedMethod;
import io.floci.gcp.services.iam.authorization.IamAuthorizationAdapter;
import io.floci.gcp.services.iam.authorization.IamOperation;
import io.floci.gcp.services.iam.authorization.IamPermissionCheck;
import io.floci.gcp.services.iam.model.StoredPolicy;
import io.grpc.Context;
import io.quarkus.arc.Arc;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Writes Cloud Audit Logs entries for the calls the IAM authorization adapters describe with
 * {@link IamAuthorizationAdapter#auditedMethod}. Transports call {@link #begin} before the call runs and
 * {@link #complete} with its outcome; both IAM authorization modes are audited. ADMIN_WRITE methods write
 * Admin Activity entries, which are "always written"; the other permission types write Data Access entries
 * only when the auditConfigs of the project's IAM policy, or of its organization's, enable that type for the
 * service or for {@code allServices} and do not exempt the caller.
 *
 * <p>Sources: https://docs.cloud.google.com/logging/docs/audit (log names, caller identity and IP),
 * {@code google/cloud/audit/audit_log.proto}, and each service's audit logging page for its methods.
 */
@ApplicationScoped
public class AuditLogRecorder implements AuditTrail {

    static final String ACTIVITY_LOG_ID = "cloudaudit.googleapis.com%2Factivity";
    static final String DATA_ACCESS_LOG_ID = "cloudaudit.googleapis.com%2Fdata_access";
    private static final String ALL_SERVICES = "allServices";

    private static final Logger LOG = Logger.getLogger(AuditLogRecorder.class);
    private static final String SERVICE_ACCOUNT_MEMBER = "serviceAccount:";

    private final Instance<CloudLoggingService> logging;
    private final Instance<IamService> iam;
    private final IamPrincipalResolver principals;
    private final ObjectMapper json;
    private final Instance<IamResourceHierarchy> hierarchy;
    private final Instance<AuditRequestScope> requestScope;

    @Inject
    public AuditLogRecorder(Instance<CloudLoggingService> logging, Instance<IamService> iam,
            IamPrincipalResolver principals, ObjectMapper json, Instance<IamResourceHierarchy> hierarchy,
            Instance<AuditRequestScope> requestScope) {
        this.logging = logging;
        this.iam = iam;
        this.principals = principals;
        this.json = json;
        this.hierarchy = hierarchy;
        this.requestScope = requestScope;
    }

    /** gRPC calls carry their {@link Scope} in the call context; REST calls in {@link AuditRequestScope}. */
    static final Context.Key<Scope> GRPC_SCOPE = Context.key("audit-scope");

    /**
     * One transport call: who made it and from where, and the entries recorded for it, completed by the
     * transport with the call's status.
     */
    public static final class Scope {
        private final String authorization;
        private final String callerIp;
        private final String userAgent;
        private final List<Call> pending = new CopyOnWriteArrayList<>();

        public Scope(String authorization, String callerIp, String userAgent) {
            this.authorization = authorization;
            this.callerIp = callerIp;
            this.userAgent = userAgent;
        }

        void add(Call call) {
            pending.add(call);
        }
    }

    /** What is known of an audited call before it runs. */
    public record Call(IamAuthorizationAdapter adapter, IamOperation operation, AuditRequest request,
            AuditedMethod method, List<IamPermissionCheck> checks, IamPrincipal principal, String callerIp,
            String userAgent, Instant time, StoredPolicy policyBefore) {
    }

    /** Records the call an adapter describes, if it does, in the transport's scope. Never fails the call. */
    public void begin(Scope scope, IamAuthorizationAdapter adapter, IamOperation operation, AuditRequest request) {
        Instant time = Instant.now();
        try {
            Optional<AuditedMethod> method = adapter.auditedMethod(operation, request);
            if (method.isEmpty()) {
                return;
            }
            scope.add(new Call(adapter, operation, request, method.get(), checks(adapter, operation),
                    principal(scope.authorization), scope.callerIp, scope.userAgent, time,
                    policy(method.get().policyResource())));
        } catch (RuntimeException e) {
            LOG.debugf(e, "No audit entry for %s on %s", operation.name(), operation.resource());
        }
    }

    /** Records a call a service describes itself, in the scope of the transport call it runs in. */
    @Override
    public void record(AuditedMethod method, List<IamPermissionCheck> checks) {
        Scope scope = currentScope();
        if (scope == null) {
            LOG.debugf("No transport call to audit %s on %s", method.methodName(), method.resourceName());
            return;
        }
        scope.add(new Call(null, null, null, method, checks, principal(scope.authorization), scope.callerIp,
                scope.userAgent, Instant.now(), policy(method.policyResource())));
    }

    /** Writes every entry recorded in the scope; {@code code} is the call's {@code google.rpc.Code}. */
    public void complete(Scope scope, int code, String message) {
        for (Call call : scope.pending) {
            complete(call, code, message);
        }
        scope.pending.clear();
    }

    private Scope currentScope() {
        Scope grpc = GRPC_SCOPE.get();
        if (grpc != null) {
            return grpc;
        }
        if (Arc.container() != null && Arc.container().requestContext().isActive()) {
            return requestScope.get().scope();
        }
        return null;
    }

    /** Writes the call's entry. Never fails the call. */
    private void complete(Call call, int code, String message) {
        try {
            if (!isAdminActivity(call.method()) && !dataAccessEnabled(call.method(), call.principal())) {
                return;
            }
            logging.get().writeLogEntries(null, null, null, null, List.of(entry(call, code, message)), false);
        } catch (RuntimeException e) {
            LOG.warnf(e, "Failed to write the audit entry for %s on %s",
                    call.method().methodName(), call.method().resourceName());
        }
    }

    private StoredLogEntry entry(Call call, int code, String message) {
        AuditedMethod method = call.method();
        Map<String, String> labels = new LinkedHashMap<>(method.resourceLabels());
        after(call).ifPresent(completed -> completed.resourceLabels().forEach((key, value) -> {
            if (value != null && !value.isEmpty()) {
                labels.put(key, value);
            }
        }));

        AuditLog.Builder audit = AuditLog.newBuilder()
                .setServiceName(method.serviceName())
                .setMethodName(method.methodName())
                .setResourceName(method.resourceName())
                .setStatus(code == Code.OK_VALUE ? Status.getDefaultInstance()
                        : Status.newBuilder().setCode(code).setMessage(message == null ? "" : message).build())
                .setAuthenticationInfo(authentication(call.principal()))
                .setRequestMetadata(RequestMetadata.newBuilder()
                        .setCallerIp(call.callerIp() == null ? "" : call.callerIp())
                        .setCallerSuppliedUserAgent(call.userAgent() == null ? "" : call.userAgent())
                        .setRequestAttributes(AttributeContext.Request.newBuilder()
                                .setTime(timestamp(call.time()))
                                .setAuth(AttributeContext.Auth.getDefaultInstance()))
                        .setDestinationAttributes(AttributeContext.Peer.getDefaultInstance()));
        // Real entries name the checked resource as resourceName does, e.g. projects/-/serviceAccounts/{uniqueId}.
        for (IamPermissionCheck check : call.checks()) {
            AuthorizationInfo.Builder authorization = AuthorizationInfo.newBuilder()
                    .setResource(method.resourceName())
                    .setPermission(check.permission())
                    .setGranted(code != Code.PERMISSION_DENIED_VALUE);
            if (method.bareAuthorization()) {
                authorization.setResourceAttributes(AttributeContext.Resource.getDefaultInstance());
            } else {
                authorization.setResourceAttributes(AttributeContext.Resource.newBuilder()
                                .setService(check.resource().service())
                                .setName(method.resourceName())
                                .setType(check.resource().type()))
                        .setPermissionType(method.permissionType());
            }
            audit.addAuthorizationInfo(authorization);
        }
        if (!method.resourceLocations().isEmpty()) {
            audit.setResourceLocation(ResourceLocation.newBuilder().addAllCurrentLocations(method.resourceLocations()));
        }
        if (method.request() != null) {
            audit.setRequest(Structs.toStruct(method.request()));
        }
        if (code == Code.OK_VALUE && call.policyBefore() != null) {
            StoredPolicy policyAfter = policy(method.policyResource());
            if (policyAfter != null) {
                audit.setServiceData(Any.pack(AuditData.newBuilder()
                        .setPolicyDelta(policyDelta(call.policyBefore(), policyAfter)).build()));
                audit.setResponse(policyResponse(policyAfter));
            }
        }

        StoredLogEntry entry = new StoredLogEntry();
        entry.setLogName(method.logParent() + "/logs/" + (isAdminActivity(method) ? ACTIVITY_LOG_ID : DATA_ACCESS_LOG_ID));
        entry.setResourceType(method.resourceType());
        entry.setResourceLabels(labels);
        entry.setSeverity(code != Code.OK_VALUE ? "ERROR" : isAdminActivity(method) ? "NOTICE" : "INFO");
        entry.setTimestamp(call.time().toString());
        entry.setProtoPayload(ProtoPayloads.fromAny(Any.pack(audit.build())));
        if (method.operation() != null) {
            entry.setOperation(method.operation());
        }
        return entry;
    }

    private static boolean isAdminActivity(AuditedMethod method) {
        return method.permissionType() == AuthorizationInfo.PermissionType.ADMIN_WRITE;
    }

    /**
     * Whether the auditConfigs of the log's resource and its ancestors enable this Data Access log type for the
     * service, and do not exempt the caller. "the resulting configuration for the service is the union of the
     * two configurations" (allServices and the service), and "If there is a configuration for a Google Cloud
     * service across the hierarchy, then the resulting configuration is the union of the configurations."
     * https://docs.cloud.google.com/logging/docs/audit/configure-data-access
     */
    private boolean dataAccessEnabled(AuditedMethod method, IamPrincipal principal) {
        String logType = method.permissionType().name();
        boolean enabled = false;
        Set<String> exempted = new LinkedHashSet<>();
        List<String> resources = method.logParent().startsWith("projects/")
                ? hierarchy.get().policyResourcesFor(new IamResource("cloudresourcemanager.googleapis.com",
                        "cloudresourcemanager.googleapis.com/Project", method.logParent(), method.logParent(),
                        method.logParent(), true))
                : List.of(method.logParent());
        for (String resource : resources) {
            StoredPolicy policy = policy(resource);
            if (policy == null || policy.getAuditConfigs() == null) {
                continue;
            }
            for (Map<String, Object> config : policy.getAuditConfigs()) {
                Object service = config.get("service");
                if (!ALL_SERVICES.equals(service) && !method.serviceName().equals(service)
                        || !(config.get("auditLogConfigs") instanceof List<?> logConfigs)) {
                    continue;
                }
                for (Object item : logConfigs) {
                    if (item instanceof Map<?, ?> logConfig && logType.equals(logConfig.get("logType"))) {
                        enabled = true;
                        if (logConfig.get("exemptedMembers") instanceof List<?> members) {
                            members.forEach(member -> exempted.add(String.valueOf(member)));
                        }
                    }
                }
            }
        }
        return enabled && !(principal.isAuthenticated() && exempted.contains(principal.member()));
    }

    private static Optional<AuditedMethod> after(Call call) {
        if (call.adapter() == null) {
            return Optional.empty();
        }
        try {
            return call.adapter().auditedMethod(call.operation(), call.request());
        } catch (RuntimeException e) {
            // A call that deleted its resource is described from before it ran.
            return Optional.empty();
        }
    }

    private static List<IamPermissionCheck> checks(IamAuthorizationAdapter adapter, IamOperation operation) {
        try {
            return adapter.checks(operation);
        } catch (RuntimeException e) {
            LOG.debugf(e, "No permission mapping for the audit entry of %s", operation.name());
            return List.of();
        }
    }

    private IamPrincipal principal(String authorization) {
        try {
            return principals.resolve(authorization).principal();
        } catch (RuntimeException e) {
            // A refused credential (a disabled account) fails the call itself; the entry has no principal.
            return IamPrincipal.anonymous();
        }
    }

    private StoredPolicy policy(String resource) {
        if (resource == null) {
            return null;
        }
        try {
            return iam.get().getPolicy(resource);
        } catch (RuntimeException e) {
            LOG.debugf(e, "No IAM policy for the audit entry of %s", resource);
            return null;
        }
    }

    private static AuthenticationInfo authentication(IamPrincipal principal) {
        AuthenticationInfo.Builder builder = AuthenticationInfo.newBuilder();
        if (principal.isAuthenticated()) {
            String member = principal.member();
            if (member.startsWith(SERVICE_ACCOUNT_MEMBER)) {
                builder.setPrincipalEmail(member.substring(SERVICE_ACCOUNT_MEMBER.length()));
            }
            builder.setPrincipalSubject(member);
        }
        return builder.build();
    }

    static PolicyDelta policyDelta(StoredPolicy before, StoredPolicy after) {
        Set<Grant> old = grants(before);
        Set<Grant> current = grants(after);
        PolicyDelta.Builder delta = PolicyDelta.newBuilder();
        for (Grant grant : current) {
            if (!old.contains(grant)) {
                delta.addBindingDeltas(grant.delta(BindingDelta.Action.ADD));
            }
        }
        for (Grant grant : old) {
            if (!current.contains(grant)) {
                delta.addBindingDeltas(grant.delta(BindingDelta.Action.REMOVE));
            }
        }
        return delta.build();
    }

    private Struct policyResponse(StoredPolicy policy) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("@type", "type.googleapis.com/google.iam.v1.Policy");
        response.putAll(json.convertValue(policy, new TypeReference<Map<String, Object>>() {}));
        return Structs.toStruct(response);
    }

    private static Set<Grant> grants(StoredPolicy policy) {
        Set<Grant> grants = new LinkedHashSet<>();
        if (policy.getBindings() == null) {
            return grants;
        }
        for (Map<String, Object> binding : policy.getBindings()) {
            if (!(binding.get("role") instanceof String role) || !(binding.get("members") instanceof List<?> members)) {
                continue;
            }
            Map<?, ?> condition = binding.get("condition") instanceof Map<?, ?> map ? map : null;
            for (Object member : members) {
                grants.add(new Grant(role, String.valueOf(member), condition));
            }
        }
        return grants;
    }

    private record Grant(String role, String member, Map<?, ?> condition) {
        BindingDelta delta(BindingDelta.Action action) {
            BindingDelta.Builder delta = BindingDelta.newBuilder().setAction(action).setRole(role).setMember(member);
            if (condition != null) {
                delta.setCondition(Expr.newBuilder()
                        .setExpression(text(condition.get("expression")))
                        .setTitle(text(condition.get("title")))
                        .setDescription(text(condition.get("description"))));
            }
            return delta.build();
        }

        private static String text(Object value) {
            return value == null ? "" : String.valueOf(value);
        }
    }

    private static Timestamp timestamp(Instant instant) {
        return Timestamp.newBuilder().setSeconds(instant.getEpochSecond()).setNanos(instant.getNano()).build();
    }
}
