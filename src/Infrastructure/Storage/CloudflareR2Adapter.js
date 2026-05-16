import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectsCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import { ISyncProvider } from "../../Application/Ports/ISyncProvider.js";
import { EncryptedBlob } from "../../Domain/ValueObjects/EncryptedBlob.js";

/**
 * @title CloudflareR2Adapter
 * @notice Implements remote storage synchronization via Cloudflare R2 (S3-compatible).
 * @dev Extends ISyncProvider to provide cloud persistence for Paid/Sovereign tiers.
 */

/* //////////////////////////////////////////////////////////////
                        CLOUDFLARE R2 ADAPTER
//////////////////////////////////////////////////////////////*/

export class CloudflareR2Adapter extends ISyncProvider {
  #client;
  #bucketName;

  /**
   * @notice Initializes the S3 client for Cloudflare R2.
   */
  constructor() {
    super();

    const accountId = process.env.R2_ACCOUNT_ID;
    const accessKeyId = process.env.R2_ACCESS_KEY_ID;
    const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
    this.#bucketName = process.env.R2_BUCKET_NAME;

    this.#client = new S3Client({
      region: "auto",
      endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: accessKeyId,
        secretAccessKey: secretAccessKey,
      },
    });
  }

  /* //////////////////////////////////////////////////////////////
                          STORAGE OPERATIONS
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Pushes an encrypted snapshot to Cloudflare R2.
   * @param {string} vaultId - The relative path/key in the bucket.
   * @param {EncryptedBlob} blob - The encrypted data packet.
   */
  async push(vaultId, blob) {
    try {
      const payload = JSON.stringify({
        ciphertext: blob.ciphertext,
        nonce: blob.nonce,
        tag: blob.tag,
        timestamp: Date.now()
      });

      const command = new PutObjectCommand({
        Bucket: this.#bucketName,
        Key: vaultId,
        Body: payload,
        ContentType: "application/json",
      });

      await this.#client.send(command);
    } catch (error) {
      console.error("[R2_PUSH_ERROR]", error.message);
      throw new Error(`INFRA_ERROR_R2_UPLOAD_FAILED: ${error.message}`);
    }
  }

  /**
   * @notice Pulls an encrypted snapshot from Cloudflare R2.
   * @param {string} vaultId - The relative path/key in the bucket.
   * @returns {Promise<EncryptedBlob>}
   */
  async pull(vaultId) {
    try {
      const command = new GetObjectCommand({
        Bucket: this.#bucketName,
        Key: vaultId,
      });

      const response = await this.#client.send(command);
      const rawData = await response.Body.transformToString();
      const { ciphertext, nonce, tag } = JSON.parse(rawData);

      return new EncryptedBlob(ciphertext, nonce, tag);
    } catch (error) {
      // Handle both AWS SDK error formats
      const errorCode = error.Code ?? error.name;
      if (errorCode === 'NoSuchKey' || errorCode === 'NoSuchKey' || error.$metadata?.httpStatusCode === 404) {
        throw new Error(`INFRA_ERROR_R2_RESOURCE_NOT_FOUND: ${vaultId}`);
      }
      console.error("[R2_PULL_ERROR]", error.message);
      throw new Error(`INFRA_ERROR_R2_DOWNLOAD_FAILED: ${error.message}`);
    }
  }

  /**
   * @notice Wipes all objects from the sovereign bucket (paginated for large buckets).
   * @dev GDPR Article 17 compliance via bulk deletion with pagination.
   */
  async nuke() {
    try {
      let continuationToken = undefined;

      do {
        const listCommand = new ListObjectsV2Command({
          Bucket: this.#bucketName,
          ContinuationToken: continuationToken,
        });
        const listResponse = await this.#client.send(listCommand);

        if (listResponse.Contents && listResponse.Contents.length > 0) {
          const deleteCommand = new DeleteObjectsCommand({
            Bucket: this.#bucketName,
            Delete: {
              Objects: listResponse.Contents.map((obj) => ({ Key: obj.Key })),
            },
          });
          await this.#client.send(deleteCommand);
        }

        continuationToken = listResponse.IsTruncated
          ? listResponse.NextContinuationToken
          : undefined;
      } while (continuationToken);

      console.warn("[STORAGE] Cloudflare R2 bucket wiped.");
    } catch (error) {
      console.error("[R2_NUKE_ERROR]", error.message);
      throw new Error(`INFRA_ERROR_R2_NUKE_FAILED: ${error.message}`);
    }
  }
}