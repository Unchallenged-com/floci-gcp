package io.floci.gcp.services.cloudlogging;

import jakarta.enterprise.context.RequestScoped;

/** The audit scope of the current REST request, opened by {@link AuditRestFilter}. */
@RequestScoped
public class AuditRequestScope {

    private AuditLogRecorder.Scope scope;

    public AuditLogRecorder.Scope scope() {
        return scope;
    }

    void open(AuditLogRecorder.Scope scope) {
        this.scope = scope;
    }
}
