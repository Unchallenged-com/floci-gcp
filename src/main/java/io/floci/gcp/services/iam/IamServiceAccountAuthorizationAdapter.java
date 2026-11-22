package io.floci.gcp.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.cloud.audit.AuthorizationInfo.PermissionType;
import io.floci.gcp.core.common.GcpException;
import io.floci.gcp.services.iam.authorization.AuditRequest;
import io.floci.gcp.services.iam.authorization.AuditedMethod;
import io.floci.gcp.services.iam.authorization.IamAuthorizationAdapter;
import io.floci.gcp.services.iam.authorization.IamOperation;
import io.floci.gcp.services.iam.authorization.IamPermissionCheck;
import io.floci.gcp.services.iamcredentials.IamCredentialsController;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import io.floci.gcp.services.iam.model.StoredServiceAccount;
import jakarta.inject.Inject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@ApplicationScoped
public class IamServiceAccountAuthorizationAdapter implements IamAuthorizationAdapter {

    private static final String SERVICE = "iam.googleapis.com";
    private static final String CREDENTIALS_SERVICE = "iamcredentials.googleapis.com";
    private static final Set<String> SERVICE_ACCOUNT_ADMIN = Set.of(
            "iam.serviceAccounts.create", "iam.serviceAccounts.delete", "iam.serviceAccounts.disable",
            "iam.serviceAccounts.enable", "iam.serviceAccounts.get", "iam.serviceAccounts.getIamPolicy",
            "iam.serviceAccounts.list", "iam.serviceAccounts.setIamPolicy", "iam.serviceAccounts.update");
    private static final Set<String> SERVICE_ACCOUNT_KEY_ADMIN = Set.of(
            "iam.serviceAccountKeys.create", "iam.serviceAccountKeys.delete",
            "iam.serviceAccountKeys.get", "iam.serviceAccountKeys.list",
            "iam.serviceAccounts.get", "iam.serviceAccounts.list");
    private static final Set<String> SERVICE_ACCOUNT_USER = Set.of(
            "iam.serviceAccounts.get", "iam.serviceAccounts.list");
    private static final Set<String> SERVICE_ACCOUNT_TOKEN_CREATOR = Set.of(
            "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken",
            "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt",
            "iam.serviceAccounts.get", "iam.serviceAccounts.list");

    private final Instance<IamService> iamService;

    @Inject
    public IamServiceAccountAuthorizationAdapter(Instance<IamService> iamService) {
        this.iamService = iamService;
    }

    @Override
    public String serviceName() {
        return "iam";
    }

    @Override
    public Set<Class<?>> restControllers() {
        return Set.of(IamController.class, IamCredentialsController.class);
    }

    @Override
    public Set<String> grpcServices() {
        return Set.of();
    }

    @Override
    public IamOperation restOperation(String method, Map<String, String> path, JsonNode body) {
        if (path.containsKey("serviceAccount")) {
            if (!Set.of("generateAccessToken", "generateIdToken", "signBlob", "signJwt").contains(method)) {
                throw unsupported("REST method " + method);
            }
            JsonNode delegates = body == null ? null : body.get("delegates");
            if (delegates != null && (!delegates.isArray() || !delegates.isEmpty())) {
                throw unsupported("credential delegation chains");
            }
            String operation = switch (method) {
                case "generateAccessToken" -> "GenerateAccessToken";
                case "generateIdToken" -> "GenerateIdToken";
                case "signBlob" -> "SignBlob";
                case "signJwt" -> "SignJwt";
                default -> throw unsupported("REST method " + method);
            };
            return new IamOperation(operation, serviceAccountName(path.get("serviceAccount")));
        }
        if ("getIamPolicy".equals(method)) {
            return restOperation("post", Map.of("rest", path.get("rest") + ":getIamPolicy"), body);
        }
        String rest = path.get("rest");
        if (rest == null) {
            throw unsupported("REST path for " + method);
        }
        String[] parts = rest.split("/", 3);
        if (parts.length < 2 || !"serviceAccounts".equals(parts[1])) {
            throw unsupported("REST path " + rest);
        }
        String project = parts[0];
        String identifier = parts.length == 3 ? parts[2] : null;
        String customMethod = null;
        for (String candidate : List.of("getIamPolicy", "setIamPolicy", "testIamPermissions", "signBlob",
                "disable", "enable")) {
            if (identifier != null && identifier.endsWith(":" + candidate)) {
                customMethod = candidate;
                identifier = identifier.substring(0, identifier.length() - candidate.length() - 1);
                break;
            }
        }
        if (identifier == null) {
            return switch (method.toUpperCase(Locale.ROOT)) {
                case "POST" -> new IamOperation("CreateServiceAccount", "projects/" + project);
                case "GET" -> new IamOperation("ListServiceAccounts", "projects/" + project);
                default -> throw unsupported("REST method " + method + " on serviceAccounts");
            };
        }
        int keyMarker = identifier.indexOf("/keys");
        if (keyMarker >= 0 && !identifier.substring(keyMarker).matches("/keys/?|/keys/[^/:]+")) {
            throw unsupported("REST key path " + rest);
        }
        boolean keyCollection = keyMarker >= 0 && identifier.substring(keyMarker).matches("/keys/?");
        boolean key = keyMarker >= 0 && !keyCollection;
        String account = keyMarker >= 0 ? identifier.substring(0, keyMarker) : identifier;
        String resource = serviceAccountName(project, account);
        if (key) {
            resource += "/keys/" + identifier.substring(keyMarker + "/keys/".length());
        }
        if (customMethod != null) {
            if (!"post".equals(method)) {
                throw unsupported("REST method " + method + " for " + customMethod);
            }
            return new IamOperation(switch (customMethod) {
                case "getIamPolicy" -> "GetIamPolicy";
                case "setIamPolicy" -> "SetIamPolicy";
                case "testIamPermissions" -> "TestIamPermissions";
                case "signBlob" -> "SignBlob";
                case "disable" -> "DisableServiceAccount";
                case "enable" -> "EnableServiceAccount";
                default -> throw unsupported("method " + customMethod);
            }, resource);
        }
        return switch (method.toUpperCase(Locale.ROOT)) {
            case "GET" -> keyCollection
                    ? new IamOperation("ListServiceAccountKeys", resource)
                    : new IamOperation(key ? "GetServiceAccountKey" : "GetServiceAccount", resource);
            case "POST" -> {
                if (!keyCollection) {
                    throw unsupported("POST path " + rest);
                }
                yield new IamOperation("CreateServiceAccountKey", resource);
            }
            case "PUT", "PATCH" -> {
                if (keyMarker >= 0) {
                    throw unsupported("REST path " + rest);
                }
                yield new IamOperation("UpdateServiceAccount", resource);
            }
            case "DELETE" -> new IamOperation(key ? "DeleteServiceAccountKey" : "DeleteServiceAccount", resource);
            default -> throw unsupported("REST method " + method);
        };
    }

    @Override
    public IamOperation grpcOperation(String method, JsonNode request) {
        throw unsupported("gRPC operation " + method);
    }

    @Override
    public List<IamPermissionCheck> checks(IamOperation operation) {
        if (operation.resource().contains("/keys/") && !Set.of("GetServiceAccountKey", "DeleteServiceAccountKey")
                .contains(operation.name())) {
            throw unsupported("operation " + operation.name() + " on " + operation.resource());
        }
        String permission = switch (operation.name()) {
            case "CreateServiceAccount" -> "iam.serviceAccounts.create";
            case "GetServiceAccount" -> "iam.serviceAccounts.get";
            case "ListServiceAccounts" -> "iam.serviceAccounts.list";
            case "UpdateServiceAccount" -> "iam.serviceAccounts.update";
            case "DeleteServiceAccount" -> "iam.serviceAccounts.delete";
            case "DisableServiceAccount" -> "iam.serviceAccounts.disable";
            case "EnableServiceAccount" -> "iam.serviceAccounts.enable";
            case "CreateServiceAccountKey" -> "iam.serviceAccountKeys.create";
            case "GetServiceAccountKey" -> "iam.serviceAccountKeys.get";
            case "ListServiceAccountKeys" -> "iam.serviceAccountKeys.list";
            case "DeleteServiceAccountKey" -> "iam.serviceAccountKeys.delete";
            case "GetIamPolicy" -> "iam.serviceAccounts.getIamPolicy";
            case "SetIamPolicy" -> "iam.serviceAccounts.setIamPolicy";
            case "SignBlob" -> "iam.serviceAccounts.signBlob";
            case "SignJwt" -> "iam.serviceAccounts.signJwt";
            case "GenerateAccessToken" -> "iam.serviceAccounts.getAccessToken";
            case "GenerateIdToken" -> "iam.serviceAccounts.getOpenIdToken";
            case "TestIamPermissions" -> null;
            default -> throw unsupported("operation " + operation.name());
        };
        if (permission == null) {
            return List.of();
        }
        IamResource resource = "iam.serviceAccounts.create".equals(permission)
                || "iam.serviceAccounts.list".equals(permission)
                        ? IamResource.project(operation.resource()) : requireResource(operation.resource());
        return List.of(new IamPermissionCheck(permission, resource));
    }

    /**
     * The audited methods of https://docs.cloud.google.com/iam/docs/audit-logging for the operations this
     * adapter maps, with their permission types (ADMIN_WRITE: Admin Activity; ADMIN_READ: Data Access), and the
     * IAM Credentials GenerateAccessToken and SignJwt calls, Data Access entries of
     * {@code iamcredentials.googleapis.com} as captured from Google Cloud. {@code resource} is a {@code service_account} with the account's
     * {@code email_id}, {@code project_id} and {@code unique_id}, and CreateServiceAccount names its
     * project, as real entries do.
     */
    @Override
    public Optional<AuditedMethod> auditedMethod(IamOperation operation, AuditRequest request) {
        String method = switch (operation.name()) {
            case "CreateServiceAccount", "DeleteServiceAccount", "DisableServiceAccount", "EnableServiceAccount",
                    "CreateServiceAccountKey", "DeleteServiceAccountKey" -> operation.name();
            case "UpdateServiceAccount" -> "PATCH".equalsIgnoreCase(request.transportMethod())
                    ? "PatchServiceAccount" : "UpdateServiceAccount";
            case "SetIamPolicy" -> "SetIAMPolicy";
            case "GetServiceAccount", "GetServiceAccountKey", "ListServiceAccountKeys", "GenerateAccessToken",
                    "SignJwt" -> operation.name();
            case "GetIamPolicy" -> "GetIAMPolicy";
            default -> null;
        };
        if (method == null) {
            return Optional.empty();
        }
        boolean credentials = Set.of("GenerateAccessToken", "SignJwt").contains(method);
        String methodName = credentials ? method : "google.iam.admin.v1." + method;
        PermissionType permissionType = switch (method) {
            case "GetServiceAccount", "GetServiceAccountKey", "ListServiceAccountKeys", "GetIAMPolicy" ->
                    PermissionType.ADMIN_READ;
            case "GenerateAccessToken", "SignJwt" -> PermissionType.DATA_READ;
            default -> PermissionType.ADMIN_WRITE;
        };
        if ("CreateServiceAccount".equals(method)) {
            String project = operation.resource().substring("projects/".length());
            String email = request.body().path("accountId").asText("") + "@" + project + ".iam.gserviceaccount.com";
            Map<String, Object> created = AuditedMethod.request("google.iam.admin.v1.CreateServiceAccountRequest", null);
            created.put("name", operation.resource());
            created.put("account_id", request.body().path("accountId").asText(""));
            Map<String, Object> account = new LinkedHashMap<>();
            putText(account, "display_name", request.body().path("serviceAccount").path("displayName"));
            putText(account, "description", request.body().path("serviceAccount").path("description"));
            created.put("service_account", account);
            return Optional.of(new AuditedMethod(SERVICE, methodName, operation.resource(), operation.resource(),
                    "service_account", accountLabels(project, email), created, null));
        }
        String name = operation.resource();
        int keyMarker = name.indexOf("/keys/");
        String accountName = keyMarker >= 0 ? name.substring(0, keyMarker) : name;
        String[] parts = accountName.split("/", 4);
        String project = parts[1];
        String email = parts[3];
        Map<String, String> labels = accountLabels(project, email);
        String accountId = labels.getOrDefault("unique_id", "").isEmpty() ? email : labels.get("unique_id");
        String resourceName = "projects/-/serviceAccounts/" + accountId + (keyMarker >= 0 ? name.substring(keyMarker) : "");
        Map<String, Object> audited;
        if (credentials) {
            // Captured GenerateAccessToken entries carry the request's scope and lifetime; SignJwt ones only its
            // name, never the claims to sign.
            audited = AuditedMethod.request("google.iam.credentials.v1." + method + "Request", null);
            audited.put("name", "projects/-/serviceAccounts/" + email);
            if ("GenerateAccessToken".equals(method)) {
                putIfPresent(audited, "scope", request.body().path("scope"));
                putIfPresent(audited, "lifetime", request.body().path("lifetime"));
            }
        } else if ("SetIAMPolicy".equals(method)) {
            audited = AuditedMethod.request("google.iam.v1.SetIamPolicyRequest", null);
            audited.put("resource", accountName);
            audited.put("policy", AuditedMethod.value(request.body().path("policy")));
        } else {
            audited = AuditedMethod.request("google.iam.admin.v1." + method + "Request", null);
            audited.put("name", name);
        }
        return Optional.of(new AuditedMethod(credentials ? CREDENTIALS_SERVICE : SERVICE, methodName, resourceName,
                "projects/" + project, "service_account", labels, audited,
                "SetIAMPolicy".equals(method) ? accountName : null, permissionType));
    }

    private Map<String, String> accountLabels(String project, String email) {
        Map<String, String> labels = new LinkedHashMap<>();
        labels.put("email_id", email);
        labels.put("project_id", project);
        labels.put("unique_id", iamService.get().findServiceAccount(email).map(StoredServiceAccount::getUniqueId)
                .orElse(""));
        return labels;
    }

    private static void putIfPresent(Map<String, Object> target, String key, JsonNode value) {
        Object converted = AuditedMethod.value(value);
        if (converted != null) {
            target.put(key, converted);
        }
    }

    private static void putText(Map<String, Object> target, String key, JsonNode value) {
        if (value.isTextual()) {
            target.put(key, value.asText());
        }
    }

    @Override
    public Optional<IamResource> resource(String name) {
        if (name.matches("projects/[^/:]+/serviceAccounts/[^/:]+/keys/[^/:]+")) {
            int marker = name.indexOf("/keys/");
            IamResource account = resource(name.substring(0, marker)).orElseThrow();
            return Optional.of(new IamResource(SERVICE, SERVICE + "/Key",
                    account.name() + name.substring(marker), account.policyResource(), account.projectResource()));
        }
        if (!name.matches("projects/[^/:]+/serviceAccounts/[^/:]+")) {
            return Optional.empty();
        }
        String[] parts = name.split("/", 4);
        String canonical = serviceAccountName(parts[1], parts[3]);
        return Optional.of(IamResource.projectChild(SERVICE, "ServiceAccount", canonical, canonical));
    }

    @Override
    public Map<String, Set<String>> roles() {
        return Map.of(
                "roles/iam.serviceAccountAdmin", withProjectRead(SERVICE_ACCOUNT_ADMIN),
                "roles/iam.serviceAccountKeyAdmin", withProjectRead(SERVICE_ACCOUNT_KEY_ADMIN),
                "roles/iam.serviceAccountUser", withProjectRead(SERVICE_ACCOUNT_USER),
                "roles/iam.serviceAccountTokenCreator", withProjectRead(SERVICE_ACCOUNT_TOKEN_CREATOR));
    }

    @Override
    public Map<String, Set<String>> basicRoles() {
        Set<String> viewer = Set.of("iam.serviceAccounts.get", "iam.serviceAccounts.list",
                "iam.serviceAccounts.getIamPolicy", "iam.serviceAccountKeys.get", "iam.serviceAccountKeys.list");
        Set<String> editor = Stream.concat(viewer.stream(), Stream.of(
                "iam.serviceAccounts.create", "iam.serviceAccounts.update", "iam.serviceAccounts.delete",
                "iam.serviceAccounts.disable", "iam.serviceAccounts.enable",
                "iam.serviceAccountKeys.create", "iam.serviceAccountKeys.delete"))
                .collect(Collectors.toUnmodifiableSet());
        Set<String> owner = Stream.concat(editor.stream(), Stream.of("iam.serviceAccounts.setIamPolicy"))
                .collect(Collectors.toUnmodifiableSet());
        return Map.of("roles/viewer", viewer, "roles/editor", editor, "roles/owner", owner);
    }

    private static Set<String> withProjectRead(Set<String> permissions) {
        return Stream.concat(permissions.stream(), Stream.of("resourcemanager.projects.get"))
                .collect(Collectors.toUnmodifiableSet());
    }

    private String serviceAccountName(String value) {
        if (!value.contains("/") && !value.isBlank()) {
            return serviceAccountName("-", value);
        }
        throw GcpException.invalidArgument("Unsupported service account name: " + value);
    }

    private String serviceAccountName(String project, String emailOrId) {
        return iamService.get().canonicalServiceAccountName(project, emailOrId);
    }
}
