package io.floci.gcp.services.cloudlogging;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.iam.v1.GetIamPolicyRequest;
import com.google.iam.v1.SetIamPolicyRequest;
import com.google.protobuf.Message;
import io.floci.gcp.core.common.ProtoJson;
import io.floci.gcp.services.iam.authorization.AuditRequest;
import io.floci.gcp.services.iam.authorization.IamAuthorizationAdapter;
import io.floci.gcp.services.iam.authorization.IamAuthorizationRegistry;
import io.floci.gcp.services.iam.authorization.IamOperation;
import io.grpc.ForwardingServerCall.SimpleForwardingServerCall;
import io.grpc.ForwardingServerCallListener.SimpleForwardingServerCallListener;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Map;
import java.util.Optional;

/**
 * Records the unary gRPC calls that write audit entries. It wraps IAM authorization, so a
 * call that authorization refuses is recorded with its PERMISSION_DENIED status.
 */
@ApplicationScoped
public class AuditGrpcInterceptor implements ServerInterceptor {

    private static final Logger LOG = Logger.getLogger(AuditGrpcInterceptor.class);
    private static final String IAM_POLICY_SERVICE = "google.iam.v1.IAMPolicy";
    private static final Metadata.Key<String> AUTHORIZATION =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> USER_AGENT =
            Metadata.Key.of("user-agent", Metadata.ASCII_STRING_MARSHALLER);

    private final IamAuthorizationRegistry registry;
    private final AuditLogRecorder recorder;
    private final ObjectMapper mapper;

    @Inject
    public AuditGrpcInterceptor(IamAuthorizationRegistry registry, AuditLogRecorder recorder, ObjectMapper mapper) {
        this.registry = registry;
        this.recorder = recorder;
        this.mapper = mapper;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {
        if (!call.getMethodDescriptor().getType().clientSendsOneMessage()) {
            return next.startCall(call, headers);
        }
        String service = call.getMethodDescriptor().getServiceName();
        String method = call.getMethodDescriptor().getBareMethodName();
        AuditLogRecorder.Scope scope = new AuditLogRecorder.Scope(headers.get(AUTHORIZATION), callerIp(call),
                headers.get(USER_AGENT));
        ServerCall<ReqT, RespT> recording = new SimpleForwardingServerCall<>(call) {
            @Override
            public void close(Status status, Metadata trailers) {
                recorder.complete(scope, status.getCode().value(), status.getDescription());
                super.close(status, trailers);
            }
        };
        Context context = Context.current().withValue(AuditLogRecorder.GRPC_SCOPE, scope);
        return Contexts.interceptCall(context, recording, headers, (contextCall, contextHeaders) -> {
            ServerCall.Listener<ReqT> listener = next.startCall(contextCall, contextHeaders);
            return new SimpleForwardingServerCallListener<>(listener) {
                @Override
                public void onMessage(ReqT message) {
                    if (message instanceof Message proto) {
                        begin(scope, service, method, proto);
                    }
                    super.onMessage(message);
                }
            };
        });
    }

    private void begin(AuditLogRecorder.Scope scope, String service, String method, Message request) {
        try {
            String policyResource = !IAM_POLICY_SERVICE.equals(service) ? null : switch (request) {
                case SetIamPolicyRequest policy -> policy.getResource();
                case GetIamPolicyRequest policy -> policy.getResource();
                default -> null;
            };
            Optional<IamAuthorizationAdapter> adapter = IAM_POLICY_SERVICE.equals(service)
                    ? (policyResource == null ? Optional.empty() : registry.resource(policyResource))
                    : registry.grpc(service);
            if (adapter.isEmpty()) {
                return;
            }
            IamOperation operation = policyResource != null
                    ? new IamOperation(method, policyResource)
                    : adapter.get().grpcOperation(method, request);
            JsonNode body = mapper.readTree(ProtoJson.print(request));
            recorder.begin(scope, adapter.get(), operation, new AuditRequest(method, body, Map.of(), true));
        } catch (IOException | RuntimeException e) {
            LOG.debugf(e, "No audit mapping for gRPC %s/%s", service, method);
        }
    }

    private static String callerIp(ServerCall<?, ?> call) {
        SocketAddress address = call.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR);
        if (address instanceof InetSocketAddress inet && inet.getAddress() != null) {
            return inet.getAddress().getHostAddress();
        }
        return null;
    }
}
