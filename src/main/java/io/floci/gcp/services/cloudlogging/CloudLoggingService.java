package io.floci.gcp.services.cloudlogging;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.cloud.audit.AuthorizationInfo.PermissionType;
import io.floci.gcp.config.EmulatorConfig;
import io.floci.gcp.core.common.GcpException;
import io.floci.gcp.core.common.PageToken;
import io.floci.gcp.core.common.ServiceDescriptor;
import io.floci.gcp.core.common.ServiceProtocol;
import io.floci.gcp.core.common.ServiceRegistry;
import io.floci.gcp.core.storage.StorageBackend;
import io.floci.gcp.core.storage.StorageFactory;
import io.floci.gcp.lifecycle.GrpcServerManager;
import io.floci.gcp.services.cloudlogging.model.StoredLogEntry;
import io.floci.gcp.services.iam.IamResource;
import io.floci.gcp.services.iam.authorization.AuditTrail;
import io.floci.gcp.services.iam.authorization.AuditedMethod;
import io.floci.gcp.services.iam.authorization.IamAuthorizationService;
import io.floci.gcp.services.iam.authorization.IamPermissionCheck;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@ApplicationScoped
public class CloudLoggingService {

    private static final Logger LOG = Logger.getLogger(CloudLoggingService.class);
    // The _Required sink's inclusion filter (https://docs.cloud.google.com/logging/docs/routing/overview).
    private static final String PRIVATE_LOG_ENTRIES_LIST = "logging.privateLogEntries.list";
    private static final Set<String> REQUIRED_LOG_IDS = Set.of("cloudaudit.googleapis.com/activity",
            "externalaudit.googleapis.com/activity", "cloudaudit.googleapis.com/system_event",
            "externalaudit.googleapis.com/system_event", "cloudaudit.googleapis.com/access_transparency",
            "externalaudit.googleapis.com/access_transparency");

    private final StorageBackend<String, StoredLogEntry> entryStore;
    private final AtomicLong sequence = new AtomicLong(0);

    private final ServiceRegistry serviceRegistry;
    private final EmulatorConfig config;
    private final GrpcServerManager grpcServerManager;
    private final CloudLoggingSinkService sinkService;
    private final CloudLoggingMetricService metricService;
    private final Instance<AuditTrail> auditTrail;
    private final Instance<IamAuthorizationService> authorization;

    @Inject
    public CloudLoggingService(ServiceRegistry serviceRegistry, EmulatorConfig config,
            StorageFactory storageFactory, GrpcServerManager grpcServerManager, CloudLoggingSinkService sinkService,
            CloudLoggingMetricService metricService, Instance<AuditTrail> auditTrail,
            Instance<IamAuthorizationService> authorization) {
        this.serviceRegistry = serviceRegistry;
        this.config = config;
        this.grpcServerManager = grpcServerManager;
        this.sinkService = sinkService;
        this.metricService = metricService;
        this.auditTrail = auditTrail;
        this.authorization = authorization;
        this.entryStore = storageFactory.createGlobal("cloudlogging-entries", "cloudlogging-entries.json",
                new TypeReference<Map<String, StoredLogEntry>>() {});
    }

    CloudLoggingService(StorageBackend<String, StoredLogEntry> entryStore) {
        this.entryStore = entryStore;
        this.serviceRegistry = null;
        this.config = null;
        this.grpcServerManager = null;
        this.sinkService = null;
        this.metricService = null;
        this.auditTrail = null;
        this.authorization = null;
    }

    void onStart(@Observes StartupEvent ev) {
        serviceRegistry.register(ServiceDescriptor.builder("logging")
                .enabled(config.services().logging().enabled())
                .storageKey("logging")
                .protocol(ServiceProtocol.GRPC)
                .resourceClasses(CloudLoggingController.class, CloudLoggingConfigController.class,
                        CloudLoggingConfigHttpController.class, CloudLoggingMetricsController.class,
                        CloudLoggingMetricsHttpController.class)
                .api("logging.googleapis.com", "Cloud Logging API", CloudLoggingHttpController.class)
                .usageAdapter(new CloudLoggingServiceUsageAdapter())
                .build());
        grpcServerManager.bind(new CloudLoggingController(this));
        if (config.services().logging().enabled()) {
            grpcServerManager.bind(new CloudLoggingConfigController(sinkService));
            grpcServerManager.bind(new CloudLoggingMetricsController(metricService));
        }
    }

    // ── Write ────────────────────────────────────────────────────────────────

    public void writeLogEntries(String defaultLogName, String defaultResourceType,
            Map<String, String> defaultResourceLabels, Map<String, String> defaultLabels,
            List<StoredLogEntry> entries, boolean dryRun) {
        write(defaultLogName, defaultResourceType, defaultResourceLabels, defaultLabels, entries, dryRun, false);
    }

    /** Writes the audit recorder's own entries, the only writer of {@code cloudaudit.googleapis.com} logs. */
    void writeAuditEntries(List<StoredLogEntry> entries) {
        write(null, null, null, null, entries, false, true);
    }

    private void write(String defaultLogName, String defaultResourceType,
            Map<String, String> defaultResourceLabels, Map<String, String> defaultLabels,
            List<StoredLogEntry> entries, boolean dryRun, boolean audit) {
        if (entries.isEmpty()) {
            throw GcpException.invalidArgument("WriteLogEntries requires at least one entry");
        }
        for (StoredLogEntry entry : entries) {
            String logName = blankToNull(entry.getLogName()) != null ? entry.getLogName() : defaultLogName;
            if (blankToNull(logName) == null) {
                throw GcpException.invalidArgument(
                        "Log entry is missing a log_name and no default log_name was provided");
            }
            entry.setLogName(logName);
            if (!audit && isAuditLog(logName)) {
                throw GcpException.invalidArgument("Log entries cannot be written to the audit log " + logName);
            }

            if (entry.getResourceType() == null) {
                entry.setResourceType(defaultResourceType != null ? defaultResourceType : "global");
                if (entry.getResourceLabels() == null) {
                    entry.setResourceLabels(defaultResourceLabels);
                }
            }

            entry.setLabels(mergeLabels(defaultLabels, entry.getLabels()));

            if (blankToNull(entry.getInsertId()) == null) {
                entry.setInsertId(UUID.randomUUID().toString());
            }
            String now = Instant.now().toString();
            entry.setReceiveTimestamp(now);
            if (blankToNull(entry.getTimestamp()) == null) {
                entry.setTimestamp(now);
            }
            entry.setSequence(sequence.incrementAndGet());
        }

        if (dryRun) {
            LOG.debugf("writeLogEntries dryRun=true validated %d entries", entries.size());
            return;
        }
        for (StoredLogEntry entry : entries) {
            entryStore.put(key(entry), entry);
        }
        if (sinkService != null) {
            sinkService.exportEntries(entries);
        }
        if (metricService != null) {
            metricService.record(entries);
        }
        LOG.debugf("writeLogEntries stored %d entries", entries.size());
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    public PageToken.Page<StoredLogEntry> listLogEntries(List<String> resourceNames, String filter,
            String orderBy, int pageSize, String pageToken) {
        audit(resourceNames, filter, orderBy, pageSize, pageToken);
        if (resourceNames == null || resourceNames.isEmpty()) {
            throw GcpException.invalidArgument("ListLogEntries requires at least one resource name");
        }
        Predicate<StoredLogEntry> filterPredicate = LogEntryFilter.parse(filter);
        List<String> prefixes = resourceNames.stream().map(r -> r + "/logs/").collect(Collectors.toList());

        Comparator<StoredLogEntry> comparator = Comparator
                .comparing(CloudLoggingService::entryInstant)
                .thenComparingLong(StoredLogEntry::getSequence);
        if (orderBy != null && orderBy.toLowerCase().contains("desc")) {
            comparator = comparator.reversed();
        }

        List<StoredLogEntry> matched = entryStore.scan(k -> true).stream()
                .filter(e -> prefixes.stream().anyMatch(p -> e.getLogName().startsWith(p)))
                .filter(filterPredicate)
                .filter(this::readableByCaller)
                .sorted(comparator)
                .collect(Collectors.toList());

        return PageToken.paginate(matched, pageSize, pageToken);
    }

    /**
     * ListLogEntries is a Data Access (DATA_READ) method of https://docs.cloud.google.com/logging/docs/audit-logging,
     * recorded once per project it reads, before the call runs so a refused or invalid call is recorded too. The
     * entry names an {@code audited_resource}, the monitored resource "A Google Cloud resource that produces an
     * audit log" (https://docs.cloud.google.com/logging/docs/api/v2/resource-list).
     */
    private void audit(List<String> resourceNames, String filter, String orderBy, int pageSize, String pageToken) {
        if (auditTrail == null || !auditTrail.isResolvable() || resourceNames == null) {
            return;
        }
        String method = "google.logging.v2.LoggingServiceV2.ListLogEntries";
        for (String resource : resourceNames) {
            if (resource == null || !resource.matches("projects/[^/]+")) {
                continue;
            }
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("@type", "type.googleapis.com/google.logging.v2.ListLogEntriesRequest");
            request.put("resourceNames", List.copyOf(resourceNames));
            if (filter != null && !filter.isEmpty()) {
                request.put("filter", filter);
            }
            if (orderBy != null && !orderBy.isEmpty()) {
                request.put("orderBy", orderBy);
            }
            if (pageSize != 0) {
                request.put("pageSize", pageSize);
            }
            if (pageToken != null && !pageToken.isEmpty()) {
                request.put("pageToken", pageToken);
            }
            Map<String, String> labels = new LinkedHashMap<>();
            labels.put("method", method);
            labels.put("project_id", resource.substring("projects/".length()));
            labels.put("service", "logging.googleapis.com");
            auditTrail.get().record(new AuditedMethod("logging.googleapis.com", method, resource, resource,
                    "audited_resource", labels, request, null, PermissionType.DATA_READ),
                    List.of(new IamPermissionCheck("logging.logEntries.list", IamResource.project(resource))));
        }
    }

    /**
     * Data Access audit logs need {@code logging.privateLogEntries.list}: Logs Viewer "cannot view Data Access audit
     * logs that are in the _Default bucket", Private Logs Viewer can (https://docs.cloud.google.com/logging/docs/audit).
     * In enforce mode an evaluated caller without it does not see them; other callers see every entry.
     */
    private boolean readableByCaller(StoredLogEntry entry) {
        if (authorization == null || !authorization.isResolvable()
                || !"cloudaudit.googleapis.com/data_access".equals(logId(entry.getLogName()))) {
            return true;
        }
        String project = entry.getLogName().substring(0, entry.getLogName().indexOf("/logs/"));
        return !authorization.get().testPermissions(project, List.of(PRIVATE_LOG_ENTRIES_LIST)).isEmpty();
    }

    /** The audit logs Cloud Audit Logs writes, named {@code {parent}/logs/cloudaudit.googleapis.com%2F{type}}. */
    static boolean isAuditLog(String logName) {
        return logId(logName).startsWith("cloudaudit.googleapis.com/");
    }

    /** The decoded log ID of a log name, such as {@code cloudaudit.googleapis.com/activity}. */
    static String logId(String logName) {
        int marker = logName.indexOf("/logs/");
        return marker < 0 ? "" : URLDecoder.decode(logName.substring(marker + "/logs/".length()), StandardCharsets.UTF_8);
    }

    public List<String> listLogs(String parent) {
        String prefix = parent + "/logs/";
        return entryStore.scan(k -> true).stream()
                .map(StoredLogEntry::getLogName)
                .filter(name -> name.startsWith(prefix))
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }

    public void deleteLog(String logName) {
        if (logName != null && REQUIRED_LOG_IDS.contains(logId(logName))) {
            // logs.delete "Deletes all the log entries in a log for the global _Default Log Bucket"; these logs
            // are routed to the _Required bucket, whose entries cannot be deleted.
            throw GcpException.invalidArgument("Log entries in the _Required bucket cannot be deleted: " + logName);
        }
        List<StoredLogEntry> entries = entryStore.scan(k -> true).stream()
                .filter(e -> logName.equals(e.getLogName()))
                .collect(Collectors.toList());
        if (entries.isEmpty()) {
            throw GcpException.notFound("Log not found: " + logName);
        }
        entries.forEach(e -> entryStore.delete(key(e)));
        LOG.debugf("deleteLog removed %d entries for %s", entries.size(), logName);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static String key(StoredLogEntry entry) {
        return entry.getLogName() + "#" + entry.getSequence();
    }

    private static Instant entryInstant(StoredLogEntry entry) {
        try {
            return Instant.parse(entry.getTimestamp());
        } catch (Exception e) {
            return Instant.EPOCH;
        }
    }

    private static Map<String, String> mergeLabels(Map<String, String> defaults, Map<String, String> entryLabels) {
        if ((defaults == null || defaults.isEmpty()) && (entryLabels == null || entryLabels.isEmpty())) {
            return entryLabels;
        }
        Map<String, String> merged = new LinkedHashMap<>();
        if (defaults != null) {
            merged.putAll(defaults);
        }
        if (entryLabels != null) {
            merged.putAll(entryLabels); // entry labels win over request defaults
        }
        return merged;
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
