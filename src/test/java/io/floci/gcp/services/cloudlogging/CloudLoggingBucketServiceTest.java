package io.floci.gcp.services.cloudlogging;

import com.google.logging.v2.LogBucket;
import com.google.protobuf.FieldMask;
import io.floci.gcp.core.storage.InMemoryStorage;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CloudLoggingBucketServiceTest {

    private static final String PROJECT = "projects/retention-test";
    private static final String BUCKET = PROJECT + "/locations/global/buckets/_Default";
    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    private final SettableClock clock = new SettableClock();
    private final CloudLoggingBucketService service =
            new CloudLoggingBucketService(new InMemoryStorage<>(), new InMemoryStorage<>(), clock);

    @Test
    void shortenedRetentionHidesEntriesThatExtendingWithinSevenDaysRestores() {
        Instant entry = START.minus(Duration.ofDays(10));
        setRetention(1);
        assertFalse(retains(entry, entry));
        clock.advance(Duration.ofDays(6));
        setRetention(30);
        assertTrue(retains(entry, entry));
    }

    @Test
    void entriesExpiredForMoreThanTheGracePeriodCannotBeRestored() {
        Instant entry = START.minus(Duration.ofDays(10));
        setRetention(1);
        clock.advance(Duration.ofDays(8));
        setRetention(30);
        assertFalse(retains(entry, entry));
    }

    @Test
    void extendingRetentionDoesNotRestoreEntriesThatAgedOut() {
        Instant entry = START.minus(Duration.ofDays(40));
        setRetention(60);
        assertFalse(retains(entry, entry));
        Instant recent = START.minus(Duration.ofDays(20));
        assertTrue(retains(recent, recent));
        clock.advance(Duration.ofDays(35));
        assertTrue(retains(recent, recent), "the extended retention applies going forward");
    }

    @Test
    void retentionCountsOnlyFromWhenTheEntryWasReceived() {
        setRetention(1);
        clock.advance(Duration.ofDays(1));
        setRetention(60);
        clock.advance(Duration.ofDays(10));
        // Backdated before the one-day retention, but received under the 60-day one.
        Instant timestamp = clock.instant().minus(Duration.ofDays(40));
        assertTrue(retains(timestamp, clock.instant()));
        assertFalse(retains(clock.instant().minus(Duration.ofDays(61)), clock.instant()));
    }

    private boolean retains(Instant timestamp, Instant received) {
        return service.retention(PROJECT, CloudLoggingBucketService.DEFAULT).retains(timestamp, received);
    }

    private void setRetention(int days) {
        service.updateBucket(BUCKET, LogBucket.newBuilder().setRetentionDays(days).build(),
                FieldMask.newBuilder().addPaths("retention_days").build());
    }

    private static final class SettableClock extends Clock {
        private volatile Instant now = START;

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
