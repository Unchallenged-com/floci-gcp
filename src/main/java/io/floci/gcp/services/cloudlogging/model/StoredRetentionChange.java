package io.floci.gcp.services.cloudlogging.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

/** A change of a log bucket's retention: when it was made, in epoch milliseconds, and the new retention. */
@RegisterForReflection
public record StoredRetentionChange(long changedAtMillis, int retentionDays) {}
