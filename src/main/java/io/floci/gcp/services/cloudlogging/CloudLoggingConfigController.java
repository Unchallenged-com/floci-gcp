package io.floci.gcp.services.cloudlogging;

import com.google.logging.v2.ConfigServiceV2Grpc;
import com.google.logging.v2.CreateSinkRequest;
import com.google.logging.v2.DeleteBucketRequest;
import com.google.logging.v2.DeleteSinkRequest;
import com.google.logging.v2.GetBucketRequest;
import com.google.logging.v2.GetSinkRequest;
import com.google.logging.v2.ListBucketsRequest;
import com.google.logging.v2.ListBucketsResponse;
import com.google.logging.v2.ListSinksRequest;
import com.google.logging.v2.ListSinksResponse;
import com.google.logging.v2.LogBucket;
import com.google.logging.v2.LogSink;
import com.google.logging.v2.UpdateBucketRequest;
import com.google.logging.v2.UpdateSinkRequest;
import com.google.protobuf.Empty;
import io.floci.gcp.core.common.GcpGrpcController;
import io.grpc.stub.StreamObserver;

public class CloudLoggingConfigController extends ConfigServiceV2Grpc.ConfigServiceV2ImplBase {

    private final CloudLoggingSinkService service;
    private final CloudLoggingBucketService buckets;

    CloudLoggingConfigController(CloudLoggingSinkService service, CloudLoggingBucketService buckets) {
        this.service = service;
        this.buckets = buckets;
    }

    @Override
    public void listBuckets(ListBucketsRequest request, StreamObserver<ListBucketsResponse> observer) {
        try {
            observer.onNext(buckets.listBuckets(request.getParent(), request.getPageSize(), request.getPageToken()));
            observer.onCompleted();
        } catch (Exception e) {
            GcpGrpcController.grpcError(observer, e);
        }
    }

    @Override
    public void getBucket(GetBucketRequest request, StreamObserver<LogBucket> observer) {
        try {
            observer.onNext(buckets.getBucket(request.getName()));
            observer.onCompleted();
        } catch (Exception e) {
            GcpGrpcController.grpcError(observer, e);
        }
    }

    @Override
    public void updateBucket(UpdateBucketRequest request, StreamObserver<LogBucket> observer) {
        try {
            observer.onNext(buckets.updateBucket(request.getName(), request.getBucket(), request.getUpdateMask()));
            observer.onCompleted();
        } catch (Exception e) {
            GcpGrpcController.grpcError(observer, e);
        }
    }

    @Override
    public void deleteBucket(DeleteBucketRequest request, StreamObserver<Empty> observer) {
        try {
            buckets.deleteBucket(request.getName());
            observer.onNext(Empty.getDefaultInstance());
            observer.onCompleted();
        } catch (Exception e) {
            GcpGrpcController.grpcError(observer, e);
        }
    }

    @Override
    public void createSink(CreateSinkRequest request, StreamObserver<LogSink> observer) {
        try {
            observer.onNext(service.createSink(request.getParent(), request.getSink(), request.getUniqueWriterIdentity()));
            observer.onCompleted();
        } catch (Exception e) {
            GcpGrpcController.grpcError(observer, e);
        }
    }

    @Override
    public void getSink(GetSinkRequest request, StreamObserver<LogSink> observer) {
        try {
            observer.onNext(service.getSink(request.getSinkName()));
            observer.onCompleted();
        } catch (Exception e) {
            GcpGrpcController.grpcError(observer, e);
        }
    }

    @Override
    public void listSinks(ListSinksRequest request, StreamObserver<ListSinksResponse> observer) {
        try {
            observer.onNext(service.listSinks(request.getParent(), request.getPageSize(), request.getPageToken()));
            observer.onCompleted();
        } catch (Exception e) {
            GcpGrpcController.grpcError(observer, e);
        }
    }

    @Override
    public void updateSink(UpdateSinkRequest request, StreamObserver<LogSink> observer) {
        try {
            observer.onNext(service.updateSink(request.getSinkName(), request.getSink(),
                    request.getUpdateMask(), request.getUniqueWriterIdentity()));
            observer.onCompleted();
        } catch (Exception e) {
            GcpGrpcController.grpcError(observer, e);
        }
    }

    @Override
    public void deleteSink(DeleteSinkRequest request, StreamObserver<Empty> observer) {
        try {
            service.deleteSink(request.getSinkName());
            observer.onNext(Empty.getDefaultInstance());
            observer.onCompleted();
        } catch (Exception e) {
            GcpGrpcController.grpcError(observer, e);
        }
    }
}
