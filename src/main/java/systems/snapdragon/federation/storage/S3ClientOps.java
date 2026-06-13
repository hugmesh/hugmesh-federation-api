package systems.snapdragon.federation.storage;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Delete;
import software.amazon.awssdk.services.s3.model.DeleteObjectsRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.ObjectIdentifier;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.nio.file.Path;
import java.util.List;

/** Production {@link S3Ops} implementation backed by the real synchronous {@link S3Client}. */
class S3ClientOps implements S3Ops {

    private final S3Client s3;

    S3ClientOps(S3Client s3) {
        this.s3 = s3;
    }

    @Override
    public void put(String bucket, String key, Path file) {
        s3.putObject(PutObjectRequest.builder().bucket(bucket).key(key).build(),
                RequestBody.fromFile(file));
    }

    @Override
    public byte[] getOrNull(String bucket, String key) {
        try {
            return s3.getObjectAsBytes(
                    GetObjectRequest.builder().bucket(bucket).key(key).build()).asByteArray();
        } catch (NoSuchKeyException ex) {
            return null;
        }
    }

    @Override
    public boolean headExists(String bucket, String key) {
        try {
            s3.headObject(HeadObjectRequest.builder().bucket(bucket).key(key).build());
            return true;
        } catch (NoSuchKeyException ex) {
            return false;
        }
    }

    @Override
    public List<String> listKeys(String bucket, String prefix) {
        return s3.listObjectsV2(
                ListObjectsV2Request.builder().bucket(bucket).prefix(prefix).build())
                .contents().stream()
                .map(software.amazon.awssdk.services.s3.model.S3Object::key)
                .toList();
    }

    @Override
    public void bulkDelete(String bucket, List<String> keys) {
        List<ObjectIdentifier> ids = keys.stream()
                .map(k -> ObjectIdentifier.builder().key(k).build())
                .toList();
        s3.deleteObjects(DeleteObjectsRequest.builder()
                .bucket(bucket)
                .delete(Delete.builder().objects(ids).build())
                .build());
    }
}
