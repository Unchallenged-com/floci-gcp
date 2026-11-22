package io.floci.gcp.services.iam.authorization;

import java.util.List;

/**
 * Records an audited call from inside a service, for paths that authorize outside the adapter
 * registry's transport hooks (Cloud Storage, Cloud Logging entries). The transport that carries
 * the call completes the entry with the call's status.
 */
public interface AuditTrail {
    void record(AuditedMethod method, List<IamPermissionCheck> checks);
}
