use std::io;
use std::io::Cursor;
use std::marker::Unpin;
use std::sync::Arc;
use std::time::Instant;

use anyhow::anyhow;
use async_compression::Level as CompressionLevel;
use async_compression::tokio::bufread::{BrotliEncoder, XzEncoder, ZstdDecoder, ZstdEncoder};
use axum::{
    body::Body,
    extract::{Extension, Json},
    http::HeaderMap,
};
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use futures::StreamExt;
use futures::future::join_all;
use sea_orm::ActiveValue::Set;
use sea_orm::entity::prelude::*;
use sea_orm::{QuerySelect, TransactionTrait};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncReadExt, BufReader};
use tokio::sync::Semaphore;
use tokio::task::spawn;
use tokio_util::io::StreamReader;
use tracing::instrument;
use uuid::Uuid;

use crate::compression::{CompressionStream, CompressorFn};
use crate::config::CompressionType;
use crate::error::{ErrorKind, ServerError, ServerResult};
use crate::metrics;
use crate::narinfo::Compression;
use crate::storage::StorageBackend;
use crate::{RequestState, State};
use attic::api::v1::upload_path::{
    ATTIC_NAR_COMPRESSION, ATTIC_NAR_INFO, ATTIC_NAR_INFO_PREAMBLE_SIZE, UploadCompression,
    UploadPathNarInfo, UploadPathResult, UploadPathResultKind,
};
use attic::chunking::chunk_stream;
use attic::hash::Hash;
use attic::io::{HashReader, read_chunk_async};
use attic::util::Finally;

use crate::database::entity::Json as DbJson;
use crate::database::entity::cache;
use crate::database::entity::chunk::{self, ChunkState, Entity as Chunk};
use crate::database::entity::chunkref::{self, Entity as ChunkRef};
use crate::database::entity::nar::{self, Entity as Nar, NarState};
use crate::database::entity::object::{self, Entity as Object, InsertExt};
use crate::database::{AtticDatabase, ChunkGuard, NarGuard};

/// Number of chunks to upload to the storage backend at once.
///
/// TODO: Make this configurable
const CONCURRENT_CHUNK_UPLOADS: usize = 10;

/// Data of a chunk.
enum ChunkData {
    /// Some bytes in memory.
    Bytes(Bytes),

    /// A stream with a user-claimed hash and size that are potentially incorrect.
    Stream(Box<dyn AsyncBufRead + Send + Unpin + 'static>, Hash, usize),
}

/// Result of a chunk upload.
struct UploadChunkResult {
    guard: ChunkGuard,
    deduplicated: bool,
}

trait UploadPathNarInfoExt {
    fn to_active_model(&self) -> object::ActiveModel;
}

/// Uploads a new object to the cache.
///
/// When clients request to upload an object, we first try to increment
/// the `holders_count` of one `nar` row with same NAR hash. If rows were
/// updated, it means the NAR exists in the global cache and we can deduplicate
/// after confirming the NAR hash ("Deduplicate" case). Otherwise, we perform
/// a new upload to the storage backend ("New NAR" case).
#[instrument(skip_all)]
#[axum_macros::debug_handler]
pub(crate) async fn upload_path(
    Extension(state): Extension<State>,
    Extension(req_state): Extension<RequestState>,
    headers: HeaderMap,
    body: Body,
) -> ServerResult<Json<UploadPathResult>> {
    let enabled = state
        .config
        .upload_audit
        .unwrap_or_else(crate::audit::configured);
    let subject = req_state.auth.username();
    let mut audit = enabled.then(|| serde_json::json!({
        "cache": "", "store_path": "", "nar_hash": "", "nar_size": 0,
        "token.sub": subject,
        "token.jti": req_state.auth.token.get().and_then(|token| serde_json::to_value(token.opaque_claims()).ok()).and_then(|claims| claims.get("jti").cloned()),
        "client.address": req_state.client_address,
        "signatures": [], "signatures.valid_count": 0,
        "min-signatures": state.config.upload_verification.min_signatures,
        "policy_hook.decision": "not_configured", "policy_hook.reason": "",
        "deduplicated": false,
    }));
    let result = upload_path_inner(state, req_state, headers, body, &mut audit).await;
    let deduplicated = audit
        .as_ref()
        .and_then(|a| a["deduplicated"].as_bool())
        .unwrap_or(false);
    record_decision(&result, &audit, deduplicated);
    result
}

async fn upload_path_inner(
    state: State,
    req_state: RequestState,
    headers: HeaderMap,
    body: Body,
    audit: &mut Option<serde_json::Value>,
) -> ServerResult<Json<UploadPathResult>> {
    let started_at = Instant::now();
    let stream = body.into_data_stream();
    let stream = StreamReader::new(stream.map(|r| r.map_err(|e| io::Error::other(e.to_string()))));
    let mut stream: Box<dyn AsyncBufRead + Send + Unpin> = match headers.get(ATTIC_NAR_COMPRESSION)
    {
        Some(value) if value == UploadCompression::Zstd.as_str() => {
            Box::new(BufReader::new(ZstdDecoder::new(BufReader::new(stream))))
        }
        Some(value) => {
            let compression = value.to_str().map_err(|_| {
                ErrorKind::RequestError(anyhow!("{} has invalid encoding", ATTIC_NAR_COMPRESSION))
            })?;
            return Err(ErrorKind::RequestError(anyhow!(
                "Unsupported upload compression: {compression}"
            ))
            .into());
        }
        None => Box::new(BufReader::new(stream)),
    };

    let upload_info: UploadPathNarInfo = {
        if let Some(preamble_size_bytes) = headers.get(ATTIC_NAR_INFO_PREAMBLE_SIZE) {
            // Read from the beginning of the PUT body
            let preamble_size: usize = preamble_size_bytes
                .to_str()
                .map_err(|_| {
                    ErrorKind::RequestError(anyhow!(
                        "{} has invalid encoding",
                        ATTIC_NAR_INFO_PREAMBLE_SIZE
                    ))
                })?
                .parse()
                .map_err(|_| {
                    ErrorKind::RequestError(anyhow!(
                        "{} must be a valid unsigned integer",
                        ATTIC_NAR_INFO_PREAMBLE_SIZE
                    ))
                })?;

            if preamble_size > state.config.max_nar_info_size {
                return Err(ErrorKind::RequestError(anyhow!("Upload info is too large")).into());
            }

            let buf = BytesMut::with_capacity(preamble_size);
            let preamble = read_chunk_async(&mut stream, buf)
                .await
                .map_err(|e| ErrorKind::RequestError(e.into()))?;

            if preamble.len() != preamble_size {
                return Err(ErrorKind::RequestError(anyhow!(
                    "Upload info doesn't match specified size"
                ))
                .into());
            }

            serde_json::from_slice(&preamble).map_err(ServerError::request_error)?
        } else if let Some(nar_info_bytes) = headers.get(ATTIC_NAR_INFO) {
            // Read from X-Attic-Nar-Info header
            serde_json::from_slice(nar_info_bytes.as_bytes()).map_err(ServerError::request_error)?
        } else {
            return Err(ErrorKind::RequestError(anyhow!("{} must be set", ATTIC_NAR_INFO)).into());
        }
    };
    if let Some(audit) = audit {
        audit["cache"] = upload_info.cache.as_str().into();
        audit["store_path"] = upload_info.store_path.clone().into();
        audit["nar_hash"] = upload_info.nar_hash.to_typed_base16().into();
        audit["nar_size"] = upload_info.nar_size.into();
    }
    let cache_name = &upload_info.cache;

    let database = state.database().await?;
    let cache = req_state
        .auth
        .auth_cache(database, cache_name, |cache, permission| {
            permission.require_push()?;
            Ok(cache)
        })
        .await?;

    let username = req_state.auth.username().map(str::to_string);
    let decision = crate::upload_verification::verify(
        &state.config.upload_verification,
        &upload_info,
        username.as_deref(),
        Utc::now(),
    );
    let nar_size = upload_info.nar_size;
    if let Some(audit) = audit {
        audit["signatures"] = serde_json::to_value(&decision.signatures).unwrap_or_default();
        audit["signatures.valid_count"] = decision.valid_count.into();
    }
    if let Some(reason) = &decision.reason {
        let statuses = decision
            .signatures
            .iter()
            .map(|signature| format!("{}={:?}", signature.key_name, signature.status))
            .collect::<Vec<_>>()
            .join(", ");
        let result = Err(ErrorKind::UploadRejected(format!(
            "{}: {}; signatures: {}",
            upload_info.store_path, reason, statuses
        ))
        .into());
        return result;
    }

    // Try to acquire a lock on an existing NAR
    if let Some(existing_nar) = database.find_and_lock_nar(&upload_info.nar_hash).await? {
        // Deduplicate?
        // TODO: Fully kill chunk recovery (no more missing chunks)
        let missing_chunk = ChunkRef::find()
            .filter(chunkref::Column::NarId.eq(existing_nar.id))
            .filter(chunkref::Column::ChunkId.is_null())
            .limit(1)
            .one(database)
            .await
            .map_err(ServerError::database_error)?;

        if missing_chunk.is_none() {
            // Can actually be deduplicated
            if let Some(audit) = audit {
                audit["deduplicated"] = true.into();
            }
            let result = upload_path_dedup(
                username,
                cache,
                upload_info,
                stream,
                database,
                &state,
                existing_nar,
            )
            .await;
            record_upload(&result, nar_size, "deduplicated", started_at);
            return result;
        }
    }

    let result = upload_path_new(username, cache, upload_info, stream, database, &state).await;
    let kind = result
        .as_ref()
        .map(|result| match result.kind {
            UploadPathResultKind::Uploaded => "uploaded",
            UploadPathResultKind::Deduplicated => "deduplicated",
            _ => "unknown",
        })
        .unwrap_or("error");
    record_upload(&result, nar_size, kind, started_at);
    result
}

fn record_decision(
    result: &ServerResult<Json<UploadPathResult>>,
    audit: &Option<serde_json::Value>,
    deduplicated: bool,
) {
    let Some(mut audit) = audit.clone() else {
        return;
    };
    let event = if result.is_ok() {
        "upload.accepted"
    } else {
        "upload.rejected"
    };
    let reason = result.as_ref().err().map(ToString::to_string);
    audit["event"] = event.into();
    if let Err(error) = result
        && let ErrorKind::UploadOverwriteRejected(rejection) = error.kind()
    {
        audit["event"] = "upload.overwrite_rejected".into();
        audit["existing.nar_hash"] = rejection.existing_hash.as_str().into();
        audit["incoming.nar_hash"] = rejection.incoming_hash.as_str().into();
        audit["existing.uploader"] = rejection.existing_uploader.as_deref().into();
        audit["incoming.uploader"] = rejection.incoming_uploader.as_deref().into();
    }
    audit["outcome"] = if result.is_ok() {
        "accepted"
    } else {
        "rejected"
    }
    .into();
    audit["reason"] = reason.unwrap_or_default().into();
    audit["deduplicated"] = deduplicated.into();
    crate::audit::emit(&audit);
}

fn record_upload(
    result: &ServerResult<Json<UploadPathResult>>,
    nar_size: usize,
    kind: &'static str,
    started_at: Instant,
) {
    let outcome = if result.is_ok() { "success" } else { "error" };
    metrics::record_operation("upload", outcome, started_at.elapsed());
    metrics::add_count(
        "upload.objects",
        1,
        &[
            opentelemetry::KeyValue::new("upload.kind", kind),
            opentelemetry::KeyValue::new("operation.outcome", outcome),
        ],
    );
    metrics::add_bytes(
        "upload.nar",
        nar_size as u64,
        &[
            opentelemetry::KeyValue::new("upload.kind", kind),
            opentelemetry::KeyValue::new("operation.outcome", outcome),
        ],
    );
    tracing::info!(
        upload.kind = kind,
        nar.size = nar_size,
        operation.outcome = outcome,
        duration_ms = started_at.elapsed().as_secs_f64() * 1000.0,
        "Upload completed"
    );
}

/// Uploads a path when there is already a matching NAR in the global cache.
async fn upload_path_dedup(
    username: Option<String>,
    cache: cache::Model,
    upload_info: UploadPathNarInfo,
    stream: impl AsyncBufRead + Unpin,
    database: &DatabaseConnection,
    state: &State,
    existing_nar: NarGuard,
) -> ServerResult<Json<UploadPathResult>> {
    if state.config.require_proof_of_possession
        || state
            .config
            .upload_verification
            .enabled_for_cache(upload_info.cache.as_str())
    {
        let (mut stream, nar_compute) = HashReader::new(stream, Sha256::new());
        tokio::io::copy(&mut stream, &mut tokio::io::sink())
            .await
            .map_err(ServerError::request_error)?;

        // FIXME: errors
        let (nar_hash, nar_size) = nar_compute.get().unwrap();
        let nar_hash = Hash::Sha256((&nar_hash[..]).try_into().unwrap());

        // Confirm that the NAR Hash and Size are correct
        if nar_hash.to_typed_base16() != existing_nar.nar_hash
            || *nar_size != upload_info.nar_size
            || *nar_size != existing_nar.nar_size as usize
        {
            return Err(ErrorKind::RequestError(anyhow!("Bad NAR Hash or Size")).into());
        }
    }

    // Finally...

    // Create a mapping granting the local cache access to the NAR
    let txn = database
        .begin()
        .await
        .map_err(ServerError::database_error)?;
    store_object(&txn, &cache, &upload_info, existing_nar.id, username, state).await?;
    txn.commit().await.map_err(ServerError::database_error)?;

    // Ensure it's not unlocked earlier
    drop(existing_nar);

    Ok(Json(UploadPathResult {
        kind: UploadPathResultKind::Deduplicated,
        file_size: None, // TODO: Sum the chunks
        frac_deduplicated: None,
    }))
}

/// Uploads a path when there is no matching NAR in the global cache.
///
/// It's okay if some other client races to upload the same NAR before
/// us. The `nar` table can hold duplicate NARs which can be deduplicated
/// in a background process.
async fn upload_path_new(
    username: Option<String>,
    cache: cache::Model,
    upload_info: UploadPathNarInfo,
    stream: impl AsyncBufRead + Send + Unpin + 'static,
    database: &DatabaseConnection,
    state: &State,
) -> ServerResult<Json<UploadPathResult>> {
    let nar_size_threshold = state.config.chunking.nar_size_threshold;

    if nar_size_threshold == 0 || upload_info.nar_size < nar_size_threshold {
        upload_path_new_unchunked(username, cache, upload_info, stream, database, state).await
    } else {
        upload_path_new_chunked(username, cache, upload_info, stream, database, state).await
    }
}

/// Uploads a path when there is no matching NAR in the global cache (chunked).
async fn upload_path_new_chunked(
    username: Option<String>,
    cache: cache::Model,
    upload_info: UploadPathNarInfo,
    stream: impl AsyncBufRead + Send + Unpin + 'static,
    database: &DatabaseConnection,
    state: &State,
) -> ServerResult<Json<UploadPathResult>> {
    let chunking_config = &state.config.chunking;
    let compression_config = &state.config.compression;
    let compression_type = compression_config.r#type;
    let compression_level = compression_config.level();
    let compression: Compression = compression_type.into();

    let nar_size_db = i64::try_from(upload_info.nar_size).map_err(ServerError::request_error)?;

    // Create a pending NAR entry
    let nar_id = {
        let model = nar::ActiveModel {
            state: Set(NarState::PendingUpload),
            compression: Set(compression.to_string()),

            nar_hash: Set(upload_info.nar_hash.to_typed_base16()),
            nar_size: Set(nar_size_db),

            num_chunks: Set(0),

            created_at: Set(Utc::now()),
            ..Default::default()
        };

        let insertion = Nar::insert(model)
            .exec(database)
            .await
            .map_err(ServerError::database_error)?;

        insertion.last_insert_id
    };

    let cleanup = Finally::new({
        let database = database.clone();
        let nar_model = nar::ActiveModel {
            id: Set(nar_id),
            ..Default::default()
        };

        async move {
            tracing::warn!("Error occurred - Cleaning up NAR entry");

            if let Err(e) = Nar::delete(nar_model).exec(&database).await {
                tracing::warn!("Failed to unregister failed NAR: {}", e);
            }
        }
    });

    let limit = if state
        .config
        .upload_verification
        .enabled_for_cache(upload_info.cache.as_str())
    {
        u64::MAX
    } else {
        upload_info.nar_size as u64
    };
    let stream = stream.take(limit);
    let (stream, nar_compute) = HashReader::new(stream, Sha256::new());
    let mut chunks = chunk_stream(
        stream,
        chunking_config.min_size,
        chunking_config.avg_size,
        chunking_config.max_size,
    );

    let upload_chunk_limit = Arc::new(Semaphore::new(CONCURRENT_CHUNK_UPLOADS));
    let mut futures = Vec::new();

    let mut chunk_idx = 0;
    while let Some(bytes) = chunks.next().await {
        let bytes = bytes.map_err(ServerError::request_error)?;
        let data = ChunkData::Bytes(bytes);

        // Wait for a permit before spawning
        //
        // We want to block the receive process as well, otherwise it stays ahead and
        // consumes too much memory
        let permit = upload_chunk_limit.clone().acquire_owned().await.unwrap();
        futures.push({
            let database = database.clone();
            let state = state.clone();
            let require_proof_of_possession = state.config.require_proof_of_possession;

            spawn(async move {
                let chunk = upload_chunk(
                    data,
                    compression_type,
                    compression_level,
                    database.clone(),
                    state,
                    require_proof_of_possession,
                )
                .await?;

                // Create mapping from the NAR to the chunk
                ChunkRef::insert(chunkref::ActiveModel {
                    nar_id: Set(nar_id),
                    seq: Set(chunk_idx),
                    chunk_id: Set(Some(chunk.guard.id)),
                    ..Default::default()
                })
                .exec(&database)
                .await
                .map_err(ServerError::database_error)?;

                drop(permit);
                Ok(chunk)
            })
        });

        chunk_idx += 1;
    }

    // Confirm that the NAR Hash and Size are correct
    // FIXME: errors
    let (nar_hash, nar_size) = nar_compute.get().unwrap();
    let nar_hash = Hash::Sha256((&nar_hash[..]).try_into().unwrap());

    if nar_hash != upload_info.nar_hash || *nar_size != upload_info.nar_size {
        return Err(ErrorKind::RequestError(anyhow!("Bad NAR Hash or Size")).into());
    }

    // Wait for all uploads to complete
    let chunks: Vec<UploadChunkResult> = join_all(futures)
        .await
        .into_iter()
        .map(|join_result| join_result.unwrap())
        .collect::<ServerResult<Vec<_>>>()?;

    let (file_size, deduplicated_size) =
        chunks
            .iter()
            .fold((0, 0), |(file_size, deduplicated_size), c| {
                (
                    file_size + c.guard.file_size.unwrap() as usize,
                    if c.deduplicated {
                        deduplicated_size + c.guard.chunk_size as usize
                    } else {
                        deduplicated_size
                    },
                )
            });

    // Finally...
    let txn = database
        .begin()
        .await
        .map_err(ServerError::database_error)?;

    // Set num_chunks and mark the NAR as Valid
    Nar::update(nar::ActiveModel {
        id: Set(nar_id),
        state: Set(NarState::Valid),
        num_chunks: Set(chunks.len() as i32),
        ..Default::default()
    })
    .exec(&txn)
    .await
    .map_err(ServerError::database_error)?;

    // Create a mapping granting the local cache access to the NAR
    store_object(&txn, &cache, &upload_info, nar_id, username, state).await?;

    txn.commit().await.map_err(ServerError::database_error)?;

    cleanup.cancel();

    Ok(Json(UploadPathResult {
        kind: UploadPathResultKind::Uploaded,
        file_size: Some(file_size),

        // Currently, frac_deduplicated is computed from size before compression
        frac_deduplicated: Some(deduplicated_size as f64 / *nar_size as f64),
    }))
}

/// Uploads a path when there is no matching NAR in the global cache (unchunked).
///
/// We upload the entire NAR as a single chunk.
async fn upload_path_new_unchunked(
    username: Option<String>,
    cache: cache::Model,
    upload_info: UploadPathNarInfo,
    stream: impl AsyncBufRead + Send + Unpin + 'static,
    database: &DatabaseConnection,
    state: &State,
) -> ServerResult<Json<UploadPathResult>> {
    let compression_config = &state.config.compression;
    let compression_type = compression_config.r#type;
    let compression: Compression = compression_type.into();

    // Upload the entire NAR as a single chunk
    let limit = if state
        .config
        .upload_verification
        .enabled_for_cache(upload_info.cache.as_str())
    {
        u64::MAX
    } else {
        upload_info.nar_size as u64
    };
    let stream = stream.take(limit);
    let data = ChunkData::Stream(
        Box::new(stream),
        upload_info.nar_hash.clone(),
        upload_info.nar_size,
    );
    let chunk = upload_chunk(
        data,
        compression_type,
        compression_config.level(),
        database.clone(),
        state.clone(),
        state.config.require_proof_of_possession
            || state
                .config
                .upload_verification
                .enabled_for_cache(upload_info.cache.as_str()),
    )
    .await?;
    let file_size = chunk.guard.file_size.unwrap() as usize;

    // Finally...
    let txn = database
        .begin()
        .await
        .map_err(ServerError::database_error)?;

    // Create a NAR entry
    let nar_id = {
        let model = nar::ActiveModel {
            state: Set(NarState::Valid),
            compression: Set(compression.to_string()),

            nar_hash: Set(upload_info.nar_hash.to_typed_base16()),
            nar_size: Set(chunk.guard.chunk_size),

            num_chunks: Set(1),

            created_at: Set(Utc::now()),
            ..Default::default()
        };

        let insertion = Nar::insert(model)
            .exec(&txn)
            .await
            .map_err(ServerError::database_error)?;

        insertion.last_insert_id
    };

    // Create a mapping from the NAR to the chunk
    ChunkRef::insert(chunkref::ActiveModel {
        nar_id: Set(nar_id),
        seq: Set(0),
        chunk_id: Set(Some(chunk.guard.id)),
        ..Default::default()
    })
    .exec(&txn)
    .await
    .map_err(ServerError::database_error)?;

    // Create a mapping granting the local cache access to the NAR
    store_object(&txn, &cache, &upload_info, nar_id, username, state).await?;

    txn.commit().await.map_err(ServerError::database_error)?;

    Ok(Json(UploadPathResult {
        kind: UploadPathResultKind::Uploaded,
        file_size: Some(file_size),
        frac_deduplicated: None,
    }))
}

async fn store_object(
    txn: &sea_orm::DatabaseTransaction,
    cache: &cache::Model,
    upload: &UploadPathNarInfo,
    nar_id: i64,
    username: Option<String>,
    state: &State,
) -> ServerResult<()> {
    let mut model = upload.to_active_model();
    model.cache_id = Set(cache.id);
    model.nar_id = Set(nar_id);
    model.created_at = Set(Utc::now());
    model.created_by = Set(username);
    if !state
        .config
        .upload_verification
        .enabled_for_cache(upload.cache.as_str())
        && !state.config.protect_path_overwrites
    {
        Object::insert(model)
            .on_conflict_do_update()
            .exec(txn)
            .await
            .map_err(ServerError::database_error)?;
        return Ok(());
    }
    // Serialize signature merges within each cache, including first uploads.
    cache::Entity::update_many()
        .col_expr(
            cache::Column::Priority,
            sea_orm::sea_query::Expr::col(cache::Column::Priority),
        )
        .filter(cache::Column::Id.eq(cache.id))
        .exec(txn)
        .await
        .map_err(ServerError::database_error)?;
    if let Some(existing) = Object::find()
        .filter(object::Column::CacheId.eq(cache.id))
        .filter(object::Column::StorePathHash.eq(upload.store_path_hash.to_string()))
        .one(txn)
        .await
        .map_err(ServerError::database_error)?
    {
        let nar = Nar::find_by_id(existing.nar_id)
            .one(txn)
            .await
            .map_err(ServerError::database_error)?
            .ok_or(ErrorKind::NoSuchObject)?;
        if nar.nar_hash == upload.nar_hash.to_typed_base16() {
            let mut signatures = existing.sigs.0;
            for signature in &upload.sigs {
                if !signatures.contains(signature) {
                    signatures.push(signature.clone());
                }
            }
            model.id = Set(existing.id);
            model.sigs = Set(DbJson(signatures));
            model.created_at = Set(existing.created_at);
            model.created_by = Set(existing.created_by);
            Object::update(model)
                .exec(txn)
                .await
                .map_err(ServerError::database_error)?;
            return Ok(());
        }
        if state.config.protect_path_overwrites {
            return Err(ErrorKind::UploadOverwriteRejected(Box::new(
                crate::error::OverwriteRejection {
                    store_path: upload.store_path.clone(),
                    existing_hash: nar.nar_hash,
                    incoming_hash: upload.nar_hash.to_typed_base16(),
                    existing_uploader: existing.created_by,
                    incoming_uploader: model.created_by.take().flatten(),
                },
            ))
            .into());
        }
    }
    Object::insert(model)
        .on_conflict_do_update()
        .exec(txn)
        .await
        .map_err(ServerError::database_error)?;
    Ok(())
}

/// Uploads a chunk with the desired compression.
///
/// This will automatically perform deduplication if the chunk exists.
async fn upload_chunk(
    data: ChunkData,
    compression_type: CompressionType,
    compression_level: CompressionLevel,
    database: DatabaseConnection,
    state: State,
    require_proof_of_possession: bool,
) -> ServerResult<UploadChunkResult> {
    let compression: Compression = compression_type.into();

    let given_chunk_hash = data.hash();
    let given_chunk_size = data.size();

    if let Some(existing_chunk) = database
        .find_and_lock_chunk(&given_chunk_hash, compression)
        .await?
    {
        // There's an existing chunk matching the hash
        if require_proof_of_possession && !data.is_hash_trusted() {
            let stream = data.into_async_buf_read();

            let (mut stream, nar_compute) = HashReader::new(stream, Sha256::new());
            tokio::io::copy(&mut stream, &mut tokio::io::sink())
                .await
                .map_err(ServerError::request_error)?;

            // FIXME: errors
            let (nar_hash, nar_size) = nar_compute.get().unwrap();
            let nar_hash = Hash::Sha256((&nar_hash[..]).try_into().unwrap());

            // Confirm that the NAR Hash and Size are correct
            if nar_hash.to_typed_base16() != existing_chunk.chunk_hash
                || *nar_size != given_chunk_size
                || *nar_size != existing_chunk.chunk_size as usize
            {
                return Err(ErrorKind::RequestError(anyhow!("Bad chunk hash or size")).into());
            }
        }

        return Ok(UploadChunkResult {
            guard: existing_chunk,
            deduplicated: true,
        });
    }

    let key = format!("{}.chunk", Uuid::new_v4());

    let backend = state.storage().await?;
    let remote_file = backend.make_db_reference(key.clone()).await?;
    let remote_file_id = remote_file.remote_file_id();

    let chunk_size_db = i64::try_from(given_chunk_size).map_err(ServerError::request_error)?;

    let chunk_id = {
        let model = chunk::ActiveModel {
            state: Set(ChunkState::PendingUpload),
            compression: Set(compression.to_string()),

            // Untrusted data - To be confirmed later
            chunk_hash: Set(given_chunk_hash.to_typed_base16()),
            chunk_size: Set(chunk_size_db),

            remote_file: Set(DbJson(remote_file)),
            remote_file_id: Set(remote_file_id),

            created_at: Set(Utc::now()),
            ..Default::default()
        };

        let insertion = Chunk::insert(model)
            .exec(&database)
            .await
            .map_err(ServerError::database_error)?;

        insertion.last_insert_id
    };

    let cleanup = Finally::new({
        let database = database.clone();
        let chunk_model = chunk::ActiveModel {
            id: Set(chunk_id),
            ..Default::default()
        };
        let backend = backend.clone();
        let key = key.clone();

        async move {
            tracing::warn!("Error occurred - Cleaning up uploaded file and chunk entry");

            if let Err(e) = backend.delete_file(key).await {
                tracing::warn!("Failed to clean up failed upload: {}", e);
            }

            if let Err(e) = Chunk::delete(chunk_model).exec(&database).await {
                tracing::warn!("Failed to unregister failed chunk: {}", e);
            }
        }
    });

    // Compress and stream to the storage backend
    let compressor = get_compressor_fn(compression_type, compression_level);
    let mut stream = CompressionStream::new(data.into_async_buf_read(), compressor);

    backend
        .upload_file(key, stream.stream())
        .await
        .map_err(ServerError::storage_error)?;

    // Confirm that the chunk hash is correct
    let (chunk_hash, chunk_size) = stream.nar_hash_and_size().unwrap();
    let (file_hash, file_size) = stream.file_hash_and_size().unwrap();

    let chunk_hash = Hash::Sha256((&chunk_hash[..]).try_into().unwrap());
    let file_hash = Hash::Sha256((&file_hash[..]).try_into().unwrap());

    if chunk_hash != given_chunk_hash || *chunk_size != given_chunk_size {
        return Err(ErrorKind::RequestError(anyhow!("Bad chunk hash or size")).into());
    }

    // Finally...

    // Update the file hash and size, and set the chunk to valid
    let file_size_db = i64::try_from(*file_size).map_err(ServerError::request_error)?;
    let chunk = Chunk::update(chunk::ActiveModel {
        id: Set(chunk_id),
        state: Set(ChunkState::Valid),
        file_hash: Set(Some(file_hash.to_typed_base16())),
        file_size: Set(Some(file_size_db)),
        holders_count: Set(1),
        ..Default::default()
    })
    .exec(&database)
    .await
    .map_err(ServerError::database_error)?;

    cleanup.cancel();

    let guard = ChunkGuard::from_locked(database.clone(), chunk);

    Ok(UploadChunkResult {
        guard,
        deduplicated: false,
    })
}

/// Returns a compressor function that takes some stream as input.
fn get_compressor_fn<C: AsyncBufRead + Unpin + Send + 'static>(
    ctype: CompressionType,
    level: CompressionLevel,
) -> CompressorFn<C> {
    match ctype {
        CompressionType::None => Box::new(|c| Box::new(c)),
        CompressionType::Brotli => {
            Box::new(move |s| Box::new(BrotliEncoder::with_quality(s, level)))
        }
        CompressionType::Zstd => Box::new(move |s| Box::new(ZstdEncoder::with_quality(s, level))),
        CompressionType::Xz => Box::new(move |s| Box::new(XzEncoder::with_quality(s, level))),
    }
}

impl ChunkData {
    /// Returns the potentially-incorrect hash of the chunk.
    fn hash(&self) -> Hash {
        match self {
            Self::Bytes(bytes) => {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                let hash = hasher.finalize();
                Hash::Sha256((&hash[..]).try_into().unwrap())
            }
            Self::Stream(_, hash, _) => hash.clone(),
        }
    }

    /// Returns the potentially-incorrect size of the chunk.
    fn size(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Stream(_, _, size) => *size,
        }
    }

    /// Returns whether the hash is trusted.
    fn is_hash_trusted(&self) -> bool {
        matches!(self, ChunkData::Bytes(_))
    }

    /// Turns the data into an AsyncBufRead.
    fn into_async_buf_read(self) -> Box<dyn AsyncBufRead + Unpin + Send> {
        match self {
            Self::Bytes(bytes) => Box::new(Cursor::new(bytes)),
            Self::Stream(stream, _, _) => stream,
        }
    }
}

impl UploadPathNarInfoExt for UploadPathNarInfo {
    fn to_active_model(&self) -> object::ActiveModel {
        object::ActiveModel {
            store_path_hash: Set(self.store_path_hash.to_string()),
            store_path: Set(self.store_path.clone()),
            references: Set(DbJson(self.references.clone())),
            deriver: Set(self.deriver.clone()),
            sigs: Set(DbJson(self.sigs.clone())),
            ca: Set(self.ca.clone()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_compression::tokio::bufread::ZstdEncoder;
    use tokio::io::{AsyncReadExt, BufReader};

    #[tokio::test]
    async fn verifies_before_dedup_and_rejects_mismatched_body() {
        use crate::access::{Token, http::AuthState};
        use crate::database::migration::{Migrator, MigratorTrait};
        use crate::{RequestStateInner, StateInner};
        use attic::signing::NixKeypair;
        use axum::response::IntoResponse;
        use std::sync::atomic::AtomicBool;

        let temp = tempfile::tempdir().unwrap();
        let database_url = std::env::var("ATTIC_TEST_DATABASE_URL").unwrap_or_else(|_| {
            format!(
                "sqlite://{}?mode=rwc",
                temp.path().join("test.db").display()
            )
        });
        let template = include_str!("../../config-template.toml")
            .replace("%database_url%", &database_url)
            .replace(
                "%storage_path%",
                temp.path().join("storage").to_str().unwrap(),
            )
            .replace(
                "token-rs256-secret-base64 = \"%token_rs256_secret_base64%\"",
                "token-hs256-secret-base64 = \"dGVzdA==\"",
            );
        let key = NixKeypair::generate("alice").unwrap();
        let mut config: crate::config::Config = toml::from_str(&template).unwrap();
        config.require_proof_of_possession = false;
        config.protect_path_overwrites = true;
        config.upload_audit = Some(true);
        let exporter = opentelemetry_sdk::logs::InMemoryLogExporter::default();
        let provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        crate::audit::install(&provider);
        config.chunking.nar_size_threshold = 0;
        config.upload_verification = toml::from_str(&format!(
            "enabled=true\ntrusted-public-keys=[{:?}]",
            key.export_public_key()
        ))
        .unwrap();
        assert_eq!(config.database.url, database_url);
        let state = StateInner::new(config).await;
        let database = state.database().await.unwrap();
        Migrator::up(database, None).await.unwrap();
        cache::Entity::insert(cache::ActiveModel {
            name: Set("private".into()),
            keypair: Set(key.export_keypair()),
            is_public: Set(false),
            store_dir: Set("/nix/store".into()),
            priority: Set(40),
            upstream_cache_key_names: Set(DbJson(vec![])),
            created_at: Set(Utc::now()),
            deleted_at: Set(None),
            retention_period: Set(None),
            ..Default::default()
        })
        .exec(database)
        .await
        .unwrap();
        let mut token = Token::new("alice".into(), &(Utc::now() + chrono::Duration::hours(1)));
        token
            .get_or_insert_permission_mut("private".parse().unwrap())
            .push = true;
        let auth = AuthState::new();
        auth.token.set(token).unwrap();
        let request = Arc::new(RequestStateInner {
            auth,
            client_address: Some("127.0.0.1:1234".into()),
            api_endpoint: None,
            substituter_endpoint: None,
            host: "localhost".into(),
            client_claims_https: false,
            public_cache: AtomicBool::new(false),
        });
        let mut upload = UploadPathNarInfo {
            cache: "private".parse().unwrap(),
            store_path_hash: attic::nix_store::StorePathHash::new(
                "00000000000000000000000000000000".into(),
            )
            .unwrap(),
            store_path: "/nix/store/00000000000000000000000000000000-example".into(),
            references: vec![],
            system: None,
            deriver: None,
            sigs: vec![],
            ca: None,
            nar_hash: Hash::sha256_from_bytes(b"nar"),
            nar_size: 3,
        };
        let sign = |upload: &UploadPathNarInfo| {
            key.sign(&attic::signing::fingerprint(
                std::path::Path::new(&upload.store_path),
                &upload.nar_hash,
                upload.nar_size,
                &[] as &[&str],
            ))
        };
        upload.sigs.push(sign(&upload));
        let send = |upload: &UploadPathNarInfo, body: &'static [u8]| {
            let mut headers = HeaderMap::new();
            headers.insert(
                ATTIC_NAR_INFO,
                serde_json::to_string(upload).unwrap().parse().unwrap(),
            );
            upload_path(
                Extension(state.clone()),
                Extension(request.clone()),
                headers,
                Body::from(body),
            )
        };
        assert!(send(&upload, b"nar").await.is_ok());
        upload.sigs.clear();
        let response = send(&upload, b"nar").await.unwrap_err().into_response();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        upload.sigs.push(sign(&upload));
        let response = send(&upload, b"bad").await.unwrap_err().into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        upload.sigs.push("unregistered:preserved".into());
        assert!(send(&upload, b"nar").await.is_ok());
        upload.sigs.pop();
        assert!(send(&upload, b"nar").await.is_ok());
        let stored = Object::find().one(database).await.unwrap().unwrap();
        assert_eq!(stored.created_by.as_deref(), Some("alice"));
        assert_eq!(stored.sigs.0.len(), 2);
        assert!(stored.sigs.0.contains(&"unregistered:preserved".to_owned()));
        let original_nar = stored.nar_id;
        upload.nar_hash = Hash::sha256_from_bytes(b"bad");
        upload.sigs = vec![sign(&upload)];
        let response = send(&upload, b"bad").await.unwrap_err().into_response();
        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
        let stored = Object::find().one(database).await.unwrap().unwrap();
        assert_eq!(stored.nar_id, original_nar);
        assert_eq!(stored.sigs.0.len(), 2);
        let events: Vec<std::collections::BTreeMap<String, opentelemetry::logs::AnyValue>> =
            exporter
                .get_emitted_logs()
                .unwrap()
                .iter()
                .map(|entry| {
                    entry
                        .record
                        .attributes_iter()
                        .map(|(key, value)| (key.as_str().to_owned(), value.clone()))
                        .collect()
                })
                .collect();
        use opentelemetry::logs::AnyValue;
        assert_eq!(events.len(), 6);
        assert_eq!(
            events[0]["event"],
            AnyValue::String("upload.accepted".into())
        );
        assert_eq!(
            events[1]["event"],
            AnyValue::String("upload.rejected".into())
        );
        assert_eq!(events[2]["deduplicated"], AnyValue::Boolean(true));
        assert_eq!(
            events[5]["event"],
            AnyValue::String("upload.overwrite_rejected".into())
        );
        assert_eq!(
            events[5]["existing.nar_hash"],
            AnyValue::String(Hash::sha256_from_bytes(b"nar").to_typed_base16().into())
        );
        assert_eq!(
            events[5]["incoming.nar_hash"],
            AnyValue::String(Hash::sha256_from_bytes(b"bad").to_typed_base16().into())
        );
        assert!(
            events
                .iter()
                .all(|event| event["token.sub"] == AnyValue::String("alice".into()))
        );
        assert!(
            events
                .iter()
                .all(|event| event["client.address"] == AnyValue::String("127.0.0.1:1234".into()))
        );
        upload.nar_hash = Hash::sha256_from_bytes(b"nar");
        for (signature, expected) in [
            ("alice:!".to_owned(), "malformed"),
            (
                NixKeypair::generate("alice").unwrap().sign(b"wrong"),
                "invalid",
            ),
            (
                NixKeypair::generate("unknown").unwrap().sign(b"nar"),
                "unknown_key",
            ),
        ] {
            upload.sigs = vec![signature];
            assert_eq!(
                send(&upload, b"nar")
                    .await
                    .unwrap_err()
                    .into_response()
                    .status(),
                axum::http::StatusCode::FORBIDDEN
            );
            let logs = exporter.get_emitted_logs().unwrap();
            let value = &logs
                .last()
                .unwrap()
                .record
                .attributes_iter()
                .find(|(key, _)| key.as_str() == "signatures")
                .unwrap()
                .1;
            let AnyValue::String(value) = value else {
                panic!("signature details missing");
            };
            let signatures: serde_json::Value = serde_json::from_str(value.as_str()).unwrap();
            assert_eq!(signatures[0]["status"], expected);
        }
        upload.sigs = vec![sign(&upload), "concurrent:first".into()];
        let mut other: UploadPathNarInfo =
            serde_json::from_value(serde_json::to_value(&upload).unwrap()).unwrap();
        other.sigs.pop();
        other.sigs.push("concurrent:second".into());
        let (first, second) = tokio::join!(send(&upload, b"nar"), send(&other, b"nar"));
        assert!(first.is_ok());
        assert!(second.is_ok());
        let merged = Object::find().one(database).await.unwrap().unwrap();
        assert!(merged.sigs.0.contains(&"concurrent:first".into()));
        assert!(merged.sigs.0.contains(&"concurrent:second".into()));
        Object::delete_by_id(stored.id)
            .exec(database)
            .await
            .unwrap();
        assert!(Object::find().one(database).await.unwrap().is_none());
        crate::gc::run_garbage_collection_once(state.config.clone())
            .await
            .unwrap();
        assert!(Nar::find().all(database).await.unwrap().is_empty());
        assert!(Chunk::find().all(database).await.unwrap().is_empty());
        upload.sigs = vec![sign(&upload)];
        let trailing = send(&upload, b"nar-extra")
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(trailing.status(), axum::http::StatusCode::BAD_REQUEST);
        let mut disabled_config = state.config.clone();
        disabled_config.upload_verification = Default::default();
        let disabled_state = StateInner::new(disabled_config).await;
        upload.sigs.clear();
        upload.nar_hash = Hash::sha256_from_bytes(b"nar");
        let mut headers = HeaderMap::new();
        headers.insert(
            ATTIC_NAR_INFO,
            serde_json::to_string(&upload).unwrap().parse().unwrap(),
        );
        assert!(
            upload_path(
                Extension(disabled_state),
                Extension(request.clone()),
                headers,
                Body::from(&b"nar"[..])
            )
            .await
            .is_ok()
        );
        let logs = exporter.get_emitted_logs().unwrap();
        let attributes: std::collections::BTreeMap<_, _> = logs
            .last()
            .unwrap()
            .record
            .attributes_iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();
        assert_eq!(attributes["signatures"], AnyValue::String("[]".into()));
        assert_eq!(attributes["token.sub"], AnyValue::String("alice".into()));
        assert_eq!(
            attributes["event"],
            AnyValue::String("upload.accepted".into())
        );
        provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn decodes_zstd_upload_body() {
        let input = b"nar payload that compresses nar payload that compresses";
        let mut encoder = ZstdEncoder::new(BufReader::new(Cursor::new(input)));
        let mut compressed = Vec::new();
        encoder.read_to_end(&mut compressed).await.unwrap();

        let mut decoder = ZstdDecoder::new(BufReader::new(Cursor::new(compressed)));
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).await.unwrap();

        assert_eq!(decoded, input);
    }
}
