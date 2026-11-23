package io.floci.gcp.services.cloudlogging;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.logging.v2.LifecycleState;
import com.google.logging.v2.ListBucketsResponse;
import com.google.logging.v2.LogBucket;
import com.google.protobuf.FieldMask;
import com.google.protobuf.Timestamp;
import io.floci.gcp.core.common.GcpException;
import io.floci.gcp.core.common.PageToken;
import io.floci.gcp.core.common.ProtoJson;
import io.floci.gcp.core.storage.StorageBackend;
import io.floci.gcp.core.storage.StorageFactory;
import io.floci.gcp.services.cloudlogging.model.StoredRetentionChange;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A project's {@code _Required} and {@code _Default} log buckets in {@code global}, which every project has
 * (https://docs.cloud.google.com/logging/docs/routing/overview). Only {@code _Default}'s changes are stored.
 */
@ApplicationScoped
public class CloudLoggingBucketService {

    static final String REQUIRED = "_Required";
    static final String DEFAULT = "_Default";
    private static final String LOCATION = "global";
    // The descriptions real projects report; _Required is reported locked.
    private static final Map<String, String> DESCRIPTIONS = Map.of(REQUIRED, "Audit bucket", DEFAULT, "Default bucket");
    // _Required keeps its entries 400 days, _Default 30 unless changed (https://docs.cloud.google.com/logging/quotas).
    private static final Map<String, Integer> RETENTION_DAYS = Map.of(REQUIRED, 400, DEFAULT, 30);
    // LogBucket fields an update may name; only the ones below them are emulated.
    private static final Set<String> MUTABLE_FIELDS = Set.of("description", "retention_days", "locked",
            "analytics_enabled", "restricted_fields", "index_configs", "cmek_settings");
    private static final Set<String> EMULATED_FIELDS = Set.of("description", "retention_days");
    // "If you shorten the retention period of a log bucket, then there is a 7-day grace period in which expired
    // logs aren't deleted" (https://docs.cloud.google.com/logging/docs/buckets).
    private static final Duration GRACE_PERIOD = Duration.ofDays(7);

    private final StorageBackend<String, String> buckets;
    private final StorageBackend<String, List<StoredRetentionChange>> retentionChanges;
    private final Clock clock;
    private final Object bucketLock = new Object();

    @Inject
    public CloudLoggingBucketService(StorageFactory storageFactory) {
        this(storageFactory.createGlobal("logging", "cloudlogging-buckets.json",
                new TypeReference<Map<String, String>>() {}),
                storageFactory.createGlobal("logging", "cloudlogging-bucket-retention.json",
                        new TypeReference<Map<String, List<StoredRetentionChange>>>() {}),
                Clock.systemUTC());
    }

    CloudLoggingBucketService(StorageBackend<String, String> buckets,
            StorageBackend<String, List<StoredRetentionChange>> retentionChanges, Clock clock) {
        this.buckets = buckets;
        this.retentionChanges = retentionChanges;
        this.clock = clock;
    }

    public ListBucketsResponse listBuckets(String parent, int pageSize, String pageToken) {
        String[] parts = parent == null ? new String[0] : parent.split("/", -1);
        if (parts.length != 4 || !"projects".equals(parts[0]) || !"locations".equals(parts[2])
                || !validSegment(parts[1]) || !validSegment(parts[3])) {
            throw GcpException.invalidArgument("Invalid bucket parent: " + parent);
        }
        List<LogBucket> found = new ArrayList<>();
        if (parts[3].equals(LOCATION) || parts[3].equals("-")) {
            String project = parts[0] + "/" + parts[1];
            synchronized (bucketLock) {
                // In the order the system sinks are listed.
                found.add(read(project, REQUIRED));
                found.add(read(project, DEFAULT));
            }
        }
        PageToken.Page<LogBucket> page = PageToken.paginate(found, pageSize > 0 ? pageSize : found.size(), pageToken);
        ListBucketsResponse.Builder response = ListBucketsResponse.newBuilder().addAllBuckets(page.items());
        if (page.nextPageToken() != null) {
            response.setNextPageToken(page.nextPageToken());
        }
        return response.build();
    }

    public LogBucket getBucket(String name) {
        String[] parts = parseName(name);
        synchronized (bucketLock) {
            return read(parts[0] + "/" + parts[1], parts[5]);
        }
    }

    public LogBucket updateBucket(String name, LogBucket requested, FieldMask updateMask) {
        String[] parts = parseName(name);
        if (updateMask.getPathsCount() == 0) {
            throw GcpException.invalidArgument("Bucket update requires an update mask");
        }
        for (String path : updateMask.getPathsList()) {
            if (!MUTABLE_FIELDS.contains(path)) {
                throw GcpException.invalidArgument("Invalid bucket update mask path: " + path);
            }
        }
        String bucketId = parts[5];
        String project = parts[0] + "/" + parts[1];
        if (REQUIRED.equals(bucketId)) {
            throw requiredBucket();
        }
        for (String path : updateMask.getPathsList()) {
            if (!EMULATED_FIELDS.contains(path)) {
                throw GcpException.unimplemented("Updating the _Default bucket's " + path + " is not supported");
            }
        }
        synchronized (bucketLock) {
            LogBucket.Builder updated = read(project, bucketId).toBuilder();
            if (updateMask.getPathsList().contains("description")) {
                updated.setDescription(requested.getDescription());
            }
            if (updateMask.getPathsList().contains("retention_days")) {
                // "between 1 day and 3650 days" (https://docs.cloud.google.com/logging/docs/buckets).
                if (requested.getRetentionDays() < 1 || requested.getRetentionDays() > 3650) {
                    throw GcpException.invalidArgument("Bucket retention must be between 1 and 3650 days");
                }
                if (requested.getRetentionDays() != updated.getRetentionDays()) {
                    List<StoredRetentionChange> changes = new ArrayList<>(
                            retentionChanges.get(key(project, bucketId)).orElse(List.of()));
                    changes.add(new StoredRetentionChange(clock.millis(), requested.getRetentionDays()));
                    retentionChanges.put(key(project, bucketId), changes);
                }
                updated.setRetentionDays(requested.getRetentionDays());
            }
            LogBucket result = updated.setUpdateTime(timestamp()).build();
            buckets.put(key(project, bucketId), ProtoJson.print(result));
            return result;
        }
    }

    /** The retention of a project's {@code _Required} or {@code _Default} bucket, as of now. */
    Retention retention(String project, String bucketId) {
        synchronized (bucketLock) {
            return new Retention(RETENTION_DAYS.get(bucketId),
                    List.copyOf(retentionChanges.get(key(project, bucketId)).orElse(List.of())), clock.instant());
        }
    }

    /**
     * Whether a bucket still keeps an entry, from its retention changes. "Incoming log entries with timestamps that
     * are more than the logs retention period in the past [...] are discarded"
     * (https://docs.cloud.google.com/logging/docs/routing/overview); an entry older than the retention is not listed,
     * and is deleted unless the grace period of a shortened retention keeps it until the retention is extended.
     * "If you extend a bucket's retention period, then the retention rules apply going forward and not
     * retroactively" (https://docs.cloud.google.com/logging/docs/buckets).
     */
    record Retention(int initialDays, List<StoredRetentionChange> changes, Instant now) {

        boolean retains(Instant timestamp, Instant received) {
            Instant graceEnd = Instant.MIN;
            int days = initialDays;
            Instant periodStart = received;
            for (StoredRetentionChange change : changes) {
                Instant changedAt = Instant.ofEpochMilli(change.changedAtMillis());
                if (changedAt.isAfter(periodStart)) {
                    Instant expired = max(periodStart, timestamp.plus(Duration.ofDays(days)));
                    if (max(expired, graceEnd).isBefore(changedAt)) {
                        return false;
                    }
                    periodStart = changedAt;
                }
                // An entry already past the retention when received is discarded, grace period or not.
                if (change.retentionDays() < days && changedAt.isAfter(received)) {
                    graceEnd = changedAt.plus(GRACE_PERIOD);
                }
                days = change.retentionDays();
            }
            return !timestamp.plus(Duration.ofDays(days)).isBefore(now);
        }

        private static Instant max(Instant a, Instant b) {
            return a.isAfter(b) ? a : b;
        }
    }

    public void deleteBucket(String name) {
        String[] parts = parseName(name);
        if (REQUIRED.equals(parts[5])) {
            throw requiredBucket();
        }
        throw GcpException.failedPrecondition("The _Default bucket cannot be deleted: " + name);
    }

    /** {@code [projects, id, locations, global, buckets, bucket]}, or NOT_FOUND for a bucket a project lacks. */
    private static String[] parseName(String name) {
        String[] parts = name == null ? new String[0] : name.split("/", -1);
        if (parts.length != 6 || !"projects".equals(parts[0]) || !"locations".equals(parts[2])
                || !"buckets".equals(parts[4]) || !validSegment(parts[1]) || !validSegment(parts[3])
                || !validSegment(parts[5])) {
            throw GcpException.invalidArgument("Invalid bucket resource name: " + name);
        }
        if (!LOCATION.equals(parts[3]) || !DESCRIPTIONS.containsKey(parts[5])) {
            throw GcpException.notFound("Bucket not found: " + name);
        }
        return parts;
    }

    private static boolean validSegment(String segment) {
        return !segment.isEmpty() && !segment.equals(".") && !segment.equals("..") && !segment.matches(".*\\s.*");
    }

    private static GcpException requiredBucket() {
        // The error a locked bucket's update returns, which the _Required bucket is.
        return GcpException.failedPrecondition("This bucket is locked. Locked buckets are immutable");
    }

    private LogBucket read(String project, String bucketId) {
        return buckets.get(key(project, bucketId))
                .map(json -> ProtoJson.merge(json, LogBucket.newBuilder()).build())
                .orElseGet(() -> LogBucket.newBuilder().setName(key(project, bucketId))
                        .setDescription(DESCRIPTIONS.get(bucketId))
                        .setRetentionDays(RETENTION_DAYS.get(bucketId))
                        .setLocked(REQUIRED.equals(bucketId))
                        .setLifecycleState(LifecycleState.ACTIVE).build());
    }

    private static String key(String project, String bucketId) {
        return project + "/locations/" + LOCATION + "/buckets/" + bucketId;
    }

    private static Timestamp timestamp() {
        Instant now = Instant.now();
        return Timestamp.newBuilder().setSeconds(now.getEpochSecond()).setNanos(now.getNano()).build();
    }
}
