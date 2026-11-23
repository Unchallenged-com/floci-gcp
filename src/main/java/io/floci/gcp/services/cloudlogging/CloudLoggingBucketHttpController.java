package io.floci.gcp.services.cloudlogging;

import com.google.logging.v2.LogBucket;
import com.google.protobuf.FieldMask;
import com.google.protobuf.util.FieldMaskUtil;
import io.floci.gcp.core.common.ProtoJson;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/** Logging v2 REST {@code projects.locations.buckets}: list, get, patch and delete. */
@Path("/v2/projects/{project}/locations/{location}/buckets")
@ApplicationScoped
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class CloudLoggingBucketHttpController {

    private final CloudLoggingBucketService service;

    @Inject
    public CloudLoggingBucketHttpController(CloudLoggingBucketService service) {
        this.service = service;
    }

    @GET
    public Response listBuckets(@PathParam("project") String project, @PathParam("location") String location,
            @QueryParam("pageSize") @DefaultValue("0") int pageSize, @QueryParam("pageToken") String pageToken) {
        return json(ProtoJson.print(service.listBuckets(parent(project, location), pageSize, pageToken)));
    }

    @GET
    @Path("/{bucketId}")
    public Response getBucket(@PathParam("project") String project, @PathParam("location") String location,
            @PathParam("bucketId") String bucketId) {
        return json(ProtoJson.print(service.getBucket(parent(project, location) + "/buckets/" + bucketId)));
    }

    @PATCH
    @Path("/{bucketId}")
    public Response updateBucket(@PathParam("project") String project, @PathParam("location") String location,
            @PathParam("bucketId") String bucketId, @QueryParam("updateMask") String updateMask, String body) {
        // REST masks are lowerCamelCase; the service compares proto field names.
        FieldMask mask = FieldMaskUtil.fromJsonString(updateMask == null ? "" : updateMask);
        LogBucket bucket = ProtoJson.merge(body, LogBucket.newBuilder()).build();
        return json(ProtoJson.print(service.updateBucket(parent(project, location) + "/buckets/" + bucketId,
                bucket, mask)));
    }

    @DELETE
    @Path("/{bucketId}")
    @Consumes(MediaType.WILDCARD)
    public Response deleteBucket(@PathParam("project") String project, @PathParam("location") String location,
            @PathParam("bucketId") String bucketId) {
        service.deleteBucket(parent(project, location) + "/buckets/" + bucketId);
        return json("{}");
    }

    private static String parent(String project, String location) {
        return "projects/" + project + "/locations/" + location;
    }

    private static Response json(String body) {
        return Response.ok(body, MediaType.APPLICATION_JSON).build();
    }
}
