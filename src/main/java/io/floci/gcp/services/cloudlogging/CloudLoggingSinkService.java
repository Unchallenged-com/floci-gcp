package io.floci.gcp.services.cloudlogging;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.logging.v2.ListSinksResponse;
import com.google.logging.v2.LogExclusion;
import com.google.logging.v2.LogSink;
import com.google.protobuf.FieldMask;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.FieldMaskUtil;
import io.floci.gcp.core.common.GcpException;
import io.floci.gcp.core.common.GcpResourceNames;
import io.floci.gcp.core.common.PageToken;
import io.floci.gcp.core.common.ProjectNumbers;
import io.floci.gcp.core.common.ProtoJson;
import io.floci.gcp.core.storage.StorageBackend;
import io.floci.gcp.core.storage.StorageFactory;
import io.floci.gcp.services.cloudlogging.model.StoredLogEntry;
import io.floci.gcp.services.cloudlogging.model.StoredLogSink;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

@ApplicationScoped
public class CloudLoggingSinkService {

    private static final Logger LOG = Logger.getLogger(CloudLoggingSinkService.class);

    private static final Set<String> MUTABLE_FIELDS = Set.of("destination", "filter", "description",
            "disabled", "include_children", "exclusions", "bigquery_options");
    private static final FieldMask DEFAULT_UPDATE_MASK = FieldMask.newBuilder()
            .addPaths("destination").addPaths("filter").addPaths("include_children").build();

    private static final String STORAGE_PREFIX = "storage.googleapis.com/";

    // Every project has the _Required and _Default sinks, routing to its buckets of the same name; their filters
    // are the documented ones (https://docs.cloud.google.com/logging/docs/routing/overview).
    private static final String REQUIRED = CloudLoggingBucketService.REQUIRED;
    private static final String DEFAULT = CloudLoggingBucketService.DEFAULT;
    // The log IDs the _Required sink routes, whose entries cannot be deleted.
    static final List<String> REQUIRED_LOG_IDS = List.of("cloudaudit.googleapis.com/activity",
            "externalaudit.googleapis.com/activity", "cloudaudit.googleapis.com/system_event",
            "externalaudit.googleapis.com/system_event", "cloudaudit.googleapis.com/access_transparency",
            "externalaudit.googleapis.com/access_transparency");
    private static final String REQUIRED_FILTER = String.join(" OR ",
            REQUIRED_LOG_IDS.stream().map(id -> "LOG_ID(\"" + id + "\")").toList());
    private static final String DEFAULT_FILTER = String.join(" AND ",
            REQUIRED_LOG_IDS.stream().map(id -> "NOT LOG_ID(\"" + id + "\")").toList());
    // "You can modify and disable the _Default log sink": these are the changes emulated.
    private static final Set<String> DEFAULT_SINK_FIELDS = Set.of("filter", "description", "disabled",
            "exclusions", "include_children");

    private final StorageBackend<String, StoredLogSink> sinks;
    private final CloudLoggingGcsExporter exporter;
    private final CloudLoggingPubSubExporter pubSubExporter;
    private final CloudLoggingBigQueryExporter bigQueryExporter;
    // All sink checks and mutations share this lock; no mutable protobuf or store value escapes it.
    private final Object sinkLock = new Object();

    @Inject
    public CloudLoggingSinkService(StorageFactory storageFactory, CloudLoggingGcsExporter exporter,
            CloudLoggingPubSubExporter pubSubExporter, CloudLoggingBigQueryExporter bigQueryExporter) {
        this(storageFactory.createGlobal("logging", "cloudlogging-sinks.json",
                new TypeReference<Map<String, StoredLogSink>>() {}), exporter, pubSubExporter, bigQueryExporter);
    }

    CloudLoggingSinkService(StorageFactory storageFactory) {
        this(storageFactory, null, null, null);
    }

    CloudLoggingSinkService(StorageBackend<String, StoredLogSink> sinks) {
        this(sinks, null, null, null);
    }

    CloudLoggingSinkService(StorageBackend<String, StoredLogSink> sinks, CloudLoggingGcsExporter exporter) {
        this(sinks, exporter, null, null);
    }

    CloudLoggingSinkService(StorageBackend<String, StoredLogSink> sinks, CloudLoggingGcsExporter exporter,
            CloudLoggingPubSubExporter pubSubExporter, CloudLoggingBigQueryExporter bigQueryExporter) {
        this.sinks = sinks;
        this.exporter = exporter;
        this.pubSubExporter = pubSubExporter;
        this.bigQueryExporter = bigQueryExporter;
    }

    public LogSink createSink(String parent, LogSink requested, boolean uniqueWriterIdentity) {
        validateParent(parent);
        validateSinkId(requested.getName());
        LogSink configuration = normalizeConfiguration(requested);
        validateConfiguration(configuration);
        String name = parent + "/sinks/" + requested.getName();
        synchronized (sinkLock) {
            if (sinks.get(name).isPresent()) {
                throw GcpException.alreadyExists("Sink already exists: " + name);
            }
            boolean unique = uniqueWriterIdentity || !parent.startsWith("projects/");
            validateLegacyDestination(parent, configuration, unique);
            Timestamp now = timestamp();
            LogSink created = configuration.toBuilder()
                    .setWriterIdentity(writerIdentity(parent, unique))
                    .setCreateTime(now).setUpdateTime(now).build();
            sinks.put(name, stored(created, unique));
            return created;
        }
    }

    public LogSink getSink(String name) {
        validateSinkName(name);
        synchronized (sinkLock) {
            return current(name);
        }
    }

    public ListSinksResponse listSinks(String parent, int pageSize, String pageToken) {
        validateParent(parent);
        synchronized (sinkLock) {
            // Real projects list _Required, then _Default, before their own sinks.
            List<String> keys = new ArrayList<>();
            if (parent.startsWith("projects/")) {
                keys.add(parent + "/sinks/" + REQUIRED);
                keys.add(parent + "/sinks/" + DEFAULT);
            }
            keys.addAll(sinks.keys().stream().filter(key -> key.startsWith(parent + "/sinks/"))
                    .filter(key -> !isSystemSink(key)).sorted().toList());
            int boundedPageSize = pageSize > 0 ? Math.min(pageSize, keys.size()) : keys.size();
            PageToken.Page<String> page = PageToken.paginate(keys, boundedPageSize, pageToken);
            ListSinksResponse.Builder response = ListSinksResponse.newBuilder();
            for (String key : page.items()) {
                response.addSinks(current(key));
            }
            if (page.nextPageToken() != null) {
                response.setNextPageToken(page.nextPageToken());
            }
            return response.build();
        }
    }

    public LogSink updateSink(String name, LogSink requested, FieldMask updateMask, boolean uniqueWriterIdentity) {
        String parent = validateSinkName(name);
        String sinkId = name.substring(name.lastIndexOf('/') + 1);
        if (!requested.getName().isEmpty() && !sinkId.equals(requested.getName())) {
            throw GcpException.invalidArgument("Sink name must match the sink identifier in the resource path");
        }
        FieldMask mask = updateMask.getPathsCount() == 0 ? DEFAULT_UPDATE_MASK : updateMask;
        for (String path : mask.getPathsList()) {
            String root = path.split("\\.", 2)[0];
            if (!MUTABLE_FIELDS.contains(root) || !FieldMaskUtil.isValid(LogSink.getDescriptor(), path)
                    || path.equals("bigquery_options.uses_timestamp_column_partitioning")) {
                throw GcpException.invalidArgument("Invalid sink update mask path: " + path);
            }
        }
        if (isSystemSink(name)) {
            return updateSystemSink(name, requested, mask);
        }
        synchronized (sinkLock) {
            StoredLogSink stored = requireSink(name);
            boolean unique = uniqueWriterIdentity || !parent.startsWith("projects/");
            if (stored.uniqueWriterIdentity() && !unique) {
                throw GcpException.invalidArgument("A unique sink writer identity cannot be changed to a legacy identity");
            }
            LogSink current = read(stored);
            LogSink.Builder updated = current.toBuilder();
            FieldMaskUtil.merge(mask, requested, updated, new FieldMaskUtil.MergeOptions()
                    .setReplaceRepeatedFields(true).setReplaceMessageFields(true));
            if (unique && !stored.uniqueWriterIdentity()) {
                updated.setWriterIdentity(writerIdentity(parent, true));
            }
            updated.setUpdateTime(timestamp());
            LogSink result = normalizeConfiguration(updated.build());
            validateConfiguration(result);
            validateLegacyDestination(parent, result, unique);
            sinks.put(name, stored(result, unique));
            return result;
        }
    }

    public void deleteSink(String name) {
        validateSinkName(name);
        if (isSystemSink(name)) {
            throw systemSinkRefusal(name, true);
        }
        synchronized (sinkLock) {
            requireSink(name);
            sinks.delete(name);
        }
    }

    /**
     * The _Default sink's filter, exclusions, description and disabled flag change; its destination stays the
     * project's _Default bucket. The _Required sink cannot change.
     */
    private LogSink updateSystemSink(String name, LogSink requested, FieldMask mask) {
        if (name.endsWith("/sinks/" + REQUIRED)) {
            throw systemSinkRefusal(name, false);
        }
        synchronized (sinkLock) {
            LogSink current = current(name);
            LogSink.Builder updated = current.toBuilder();
            FieldMaskUtil.merge(mask, requested, updated, new FieldMaskUtil.MergeOptions()
                    .setReplaceRepeatedFields(true).setReplaceMessageFields(true));
            for (String path : mask.getPathsList()) {
                String root = path.split("\\.", 2)[0];
                if (!DEFAULT_SINK_FIELDS.contains(root) && !(root.equals("destination")
                        && updated.getDestination().equals(current.getDestination()))) {
                    throw GcpException.unimplemented("Changing the _Default sink's " + root + " is not supported");
                }
            }
            updated.setUpdateTime(timestamp());
            LogSink result = normalizeConfiguration(updated.build());
            validateDescriptionAndExclusions(result);
            // The _Default bucket stores what this sink routes: a filter it cannot evaluate is refused, not stored.
            SinkRouting.routes(result);
            sinks.put(name, stored(result, false));
            return result;
        }
    }

    /**
     * The project's buckets its _Required and _Default sinks route to, by bucket ID, with the entries each routes:
     * "every log sink in that resource independently evaluates it" (https://docs.cloud.google.com/logging/docs/routing/overview),
     * and "if you disable the _Default sink, then no log entries are routed to the _Default bucket"
     * (https://docs.cloud.google.com/logging/docs/export/configure_export_v2).
     */
    Map<String, Predicate<StoredLogEntry>> systemBucketRoutes(String project) {
        Map<String, Predicate<StoredLogEntry>> routes = new LinkedHashMap<>();
        for (String bucketId : List.of(REQUIRED, DEFAULT)) {
            LogSink sink;
            synchronized (sinkLock) {
                sink = current(project + "/sinks/" + bucketId);
            }
            if (!sink.getDisabled()) {
                routes.put(bucketId, SinkRouting.routes(sink));
            }
        }
        return routes;
    }

    /** The stored sink, or a project's _Required or _Default sink as the project was created with it. */
    private LogSink current(String name) {
        Optional<StoredLogSink> stored = sinks.get(name);
        if (stored.isPresent()) {
            return read(stored.get());
        }
        if (!isSystemSink(name)) {
            throw GcpException.notFound("Sink not found: " + name);
        }
        String parent = name.substring(0, name.indexOf("/sinks/"));
        String sinkId = name.substring(name.lastIndexOf('/') + 1);
        // A sink routing to a log bucket of its own project has no writer identity (logging_config.proto).
        return LogSink.newBuilder().setName(sinkId)
                .setDestination("logging.googleapis.com/" + parent + "/locations/global/buckets/" + sinkId)
                .setFilter(REQUIRED.equals(sinkId) ? REQUIRED_FILTER : DEFAULT_FILTER).build();
    }

    private static boolean isSystemSink(String name) {
        return name.startsWith("projects/")
                && (name.endsWith("/sinks/" + REQUIRED) || name.endsWith("/sinks/" + DEFAULT));
    }

    /** The errors real projects return when deleting a system sink, also used for changing _Required. */
    private static GcpException systemSinkRefusal(String name, boolean delete) {
        if (name.endsWith("/sinks/" + DEFAULT)) {
            return GcpException.permissionDenied("Sink _Default cannot be deleted. Consider disabling instead");
        }
        return GcpException.permissionDenied("Sink _Required cannot be " + (delete ? "deleted" : "updated"));
    }

    private StoredLogSink requireSink(String name) {
        return sinks.get(name).orElseThrow(() -> GcpException.notFound("Sink not found: " + name));
    }

    private static StoredLogSink stored(LogSink sink, boolean unique) {
        return new StoredLogSink(ProtoJson.print(sink), unique);
    }

    private static LogSink read(StoredLogSink sink) {
        return ProtoJson.merge(sink.json(), LogSink.newBuilder()).build();
    }

    private String writerIdentity(String parent, boolean unique) {
        if (!unique) {
            return "serviceAccount:cloud-logs@system.gserviceaccount.com";
        }
        String[] owner = parent.split("/", 2);
        String account = switch (owner[0]) {
            case "projects" -> owner[1].matches("[0-9]+") ? owner[1] : ProjectNumbers.of(owner[1]);
            case "folders" -> "folder-" + owner[1];
            case "organizations" -> "org-" + owner[1];
            case "billingAccounts" -> "billing-" + owner[1];
            default -> throw new IllegalStateException("Invalid sink owner");
        };
        return "serviceAccount:service-" + account + "@gcp-sa-logging.iam.gserviceaccount.com";
    }

    public void exportEntries(List<StoredLogEntry> entries) {
        synchronized (sinkLock) {
            for (String key : sinks.keys().stream().sorted().toList()) {
                try {
                    LogSink sink = read(requireSink(key));
                    if (sink.getDisabled()) {
                        continue;
                    }
                    String parent = key.substring(0, key.lastIndexOf("/sinks/"));
                    if (sink.getDestination().startsWith(STORAGE_PREFIX)) {
                        exporter.export(parent, sink, entries);
                    } else if (sink.getDestination().startsWith(CloudLoggingPubSubExporter.DESTINATION_PREFIX)) {
                        pubSubExporter.export(parent, sink, entries);
                    } else if (sink.getDestination().startsWith(CloudLoggingBigQueryExporter.DESTINATION_PREFIX)) {
                        bigQueryExporter.export(parent, sink, entries);
                    }
                } catch (RuntimeException exception) {
                    // Destination failures must not reject entries already accepted by Logging.
                    LOG.warnf(exception, "Cloud Logging export failed for sink %s", key);
                }
            }
        }
    }

    private static Timestamp timestamp() {
        Instant now = Instant.now();
        return Timestamp.newBuilder().setSeconds(now.getEpochSecond()).setNanos(now.getNano()).build();
    }

    private static void validateParent(String parent) {
        if (parent == null || !parent.matches("(?:projects|organizations|folders|billingAccounts)/[^/\\s]+")
                || parent.endsWith("/.") || parent.endsWith("/..")) {
            throw GcpException.invalidArgument("Invalid sink parent: " + parent);
        }
    }

    private static void validateSinkId(String id) {
        if (!id.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")) {
            throw GcpException.invalidArgument("Invalid sink identifier: " + id);
        }
    }

    private static String validateSinkName(String name) {
        if (name == null) {
            throw GcpException.invalidArgument("Sink resource name is required");
        }
        String[] parts = name.split("/", -1);
        if (parts.length != 4 || !"sinks".equals(parts[2])) {
            throw GcpException.invalidArgument("Invalid sink resource name: " + name);
        }
        String parent = parts[0] + "/" + parts[1];
        validateParent(parent);
        if (!isSystemSink(name)) {
            validateSinkId(parts[3]);
        }
        return parent;
    }

    private static void validateConfiguration(LogSink sink) {
        if (sink.getDestination().startsWith("logging.googleapis.com/")) {
            throw GcpException.unimplemented("Logging project and log-bucket sink destinations are not supported");
        }
        if (!sink.getDestination().matches("(?:storage\\.googleapis\\.com/[^/\\s]+"
                + "|pubsub\\.googleapis\\.com/projects/[^/\\s]+/topics/[^/\\s]+"
                + "|bigquery\\.googleapis\\.com/projects/[^/\\s]+/datasets/[^/\\s]+)")) {
            throw GcpException.invalidArgument("Invalid sink destination: " + sink.getDestination());
        }
        validateDescriptionAndExclusions(sink);
    }

    private static void validateDescriptionAndExclusions(LogSink sink) {
        if (sink.getDescription().length() > 8000) {
            throw GcpException.invalidArgument("Sink description must not exceed 8000 characters");
        }
        Set<String> exclusionNames = new HashSet<>();
        for (LogExclusion exclusion : sink.getExclusionsList()) {
            validateSinkId(exclusion.getName());
            if (!exclusionNames.add(exclusion.getName()) || exclusion.getFilter().isBlank()) {
                throw GcpException.invalidArgument("Sink exclusions require unique names and nonempty filters");
            }
        }
    }

    private static void validateLegacyDestination(String parent, LogSink sink, boolean unique) {
        String destinationProject = GcpResourceNames.parseProject(sink.getDestination());
        if (!unique && destinationProject != null
                && !destinationProject.equals(GcpResourceNames.parseProject(parent))) {
            throw GcpException.invalidArgument("A sink with a legacy writer identity requires a destination in its own project");
        }
    }

    private static LogSink normalizeConfiguration(LogSink sink) {
        LogSink.Builder normalized = sink.toBuilder();
        if (sink.hasBigqueryOptions()) {
            normalized.setBigqueryOptions(sink.getBigqueryOptions().toBuilder()
                    .setUsesTimestampColumnPartitioning(sink.getBigqueryOptions().getUsePartitionedTables()));
        }
        for (int i = 0; i < sink.getExclusionsCount(); i++) {
            normalized.setExclusions(i, sink.getExclusions(i).toBuilder().clearCreateTime().clearUpdateTime());
        }
        return normalized.build();
    }
}
