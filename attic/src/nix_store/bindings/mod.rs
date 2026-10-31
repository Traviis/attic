//! `libnixstore` Bindings

use std::cell::UnsafeCell;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::{Stream, StreamExt};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{AtticError, AtticResult};

// The C++ implementation takes care of concurrency
#[repr(transparent)]
pub struct FfiNixStore(UnsafeCell<cxx::UniquePtr<ffi::CNixStore>>);

unsafe impl Send for FfiNixStore {}
unsafe impl Sync for FfiNixStore {}

impl FfiNixStore {
    // The C++ implementation takes care of concurrency
    #[allow(clippy::mut_from_ref)]
    pub fn store(&self) -> Pin<&mut ffi::CNixStore> {
        unsafe {
            let ptr = self.0.get().as_mut().unwrap();
            ptr.pin_mut()
        }
    }
}

/// Obtain a handle to the Nix store.
pub unsafe fn open_nix_store() -> AtticResult<FfiNixStore> {
    match ffi::open_nix_store() {
        Ok(ptr) => {
            let cell = UnsafeCell::new(ptr);
            Ok(FfiNixStore(cell))
        }
        Err(e) => Err(e.into()),
    }
}

// TODO: Benchmark different implementations
// (tokio, crossbeam, flume)
mod mpsc {
    // Tokio
    pub use tokio::sync::mpsc::{Receiver, Sender, channel, error::SendError};
}

/// Number of buffered NAR blocks between the C++ serializer and the consumer.
///
/// The channel must be bounded: `nar_from_path` runs the synchronous C++
/// serializer on a blocking thread, which produces data as fast as the store
/// can be read, while the consumer (typically an HTTP upload) drains it at
/// network speed. With an unbounded channel the difference accumulates in
/// memory, so pushing a large store path grows RSS linearly with its size —
/// a multi-gigabyte path is enough to get the client OOM-killed.
const NAR_CHANNEL_CAPACITY: usize = 64;
const NAR_CHUNK_SIZE: usize = 64 * 1024;

/// Async write request.
#[derive(Debug)]
enum AsyncWriteMessage {
    Data(Vec<u8>),
    Error(String),
    Eof,
}

/// Async write request sender.
///
/// Every method here is called from the synchronous C++ serializer running on a
/// blocking thread (see `NixStore::nar_from_path`), never from async context,
/// so `blocking_send` is the correct way to wait for capacity: it applies
/// backpressure to the serializer instead of letting the queue grow without
/// bound.
#[derive(Clone)]
pub struct AsyncWriteSender {
    sender: mpsc::Sender<AsyncWriteMessage>,
    buf: Vec<u8>,
}

impl AsyncWriteSender {
    fn send(&mut self, data: &[u8]) -> Result<(), mpsc::SendError<AsyncWriteMessage>> {
        let mut rest = data;
        while !rest.is_empty() {
            if self.buf.capacity() == 0 {
                self.buf.reserve_exact(NAR_CHUNK_SIZE);
            }
            let take = (NAR_CHUNK_SIZE - self.buf.len()).min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == NAR_CHUNK_SIZE {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), mpsc::SendError<AsyncWriteMessage>> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = std::mem::take(&mut self.buf);
        self.sender.blocking_send(AsyncWriteMessage::Data(chunk))
    }

    fn eof(&mut self) -> Result<(), mpsc::SendError<AsyncWriteMessage>> {
        self.flush()?;
        let message = AsyncWriteMessage::Eof;
        self.sender.blocking_send(message)
    }

    pub(crate) fn rust_error(
        &mut self,
        error: impl std::error::Error,
    ) -> Result<(), impl std::error::Error> {
        let message = AsyncWriteMessage::Error(error.to_string());
        self.sender.blocking_send(message)
    }
}

/// A wrapper of the `AsyncWrite` trait for the synchronous Nix C++ land.
pub struct AsyncWriteAdapter {
    receiver: mpsc::Receiver<AsyncWriteMessage>,
    eof: bool,
}

impl AsyncWriteAdapter {
    pub fn new() -> (Self, Box<AsyncWriteSender>) {
        let (sender, receiver) = mpsc::channel(NAR_CHANNEL_CAPACITY);

        let r = Self {
            receiver,
            eof: false,
        };
        let sender = Box::new(AsyncWriteSender {
            sender,
            buf: Vec::new(),
        });

        (r, sender)
    }

    /// Write everything the sender sends to us.
    pub async fn write_all(mut self, mut writer: Box<dyn AsyncWrite + Unpin>) -> AtticResult<()> {
        let writer = writer.as_mut();

        while let Some(data) = self.next().await {
            match data {
                Ok(v) => {
                    writer.write_all(&v).await?;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        if !self.eof {
            Err(io::Error::from(io::ErrorKind::BrokenPipe).into())
        } else {
            Ok(())
        }
    }
}

impl Stream for AsyncWriteAdapter {
    type Item = AtticResult<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(message)) => {
                use AsyncWriteMessage::*;
                match message {
                    Data(v) => Poll::Ready(Some(Ok(v))),
                    Error(exception) => {
                        let error = AtticError::CxxError { exception };
                        Poll::Ready(Some(Err(error)))
                    }
                    Eof => {
                        self.eof = true;
                        Poll::Ready(None)
                    }
                }
            }
            Poll::Ready(None) => {
                if !self.eof {
                    Poll::Ready(Some(Err(io::Error::from(io::ErrorKind::BrokenPipe).into())))
                } else {
                    Poll::Ready(None)
                }
            }
        }
    }
}

#[cxx::bridge]
/// Generated by `cxx.rs`.
///
/// Mid-level wrapper of `libnixstore` implemented in C++.
mod ffi {
    extern "Rust" {
        type AsyncWriteSender;
        fn send(self: &mut AsyncWriteSender, data: &[u8]) -> Result<()>;
        fn eof(self: &mut AsyncWriteSender) -> Result<()>;
    }

    unsafe extern "C++" {
        include!("attic/src/nix_store/bindings/nix.hpp");

        // =========
        // CNixStore
        // =========

        /// Mid-level wrapper for the Unix Domain Socket Nix Store.
        type CNixStore;

        /// Returns the path of the Nix store itself.
        fn store_dir(self: Pin<&mut CNixStore>) -> String;

        /*
        /// Verifies that a path is indeed in the Nix store, then return the base store path.
        ///
        /// Use parse_store_path instead.
        fn to_store_path(self: Pin<&mut CNixStore>, path: &str) -> Result<String>;
        */

        /// Queries information about a valid path.
        fn query_path_info(
            self: Pin<&mut CNixStore>,
            store_path: &[u8],
        ) -> Result<UniquePtr<CPathInfo>>;

        /// Computes the closure of a valid path.
        ///
        /// If `flip_directions` is true, the set of paths that can reach `store_path` is
        /// returned.
        fn compute_fs_closure(
            self: Pin<&mut CNixStore>,
            store_path: &[u8],
            flip_direction: bool,
            include_outputs: bool,
            include_derivers: bool,
        ) -> Result<UniquePtr<CxxVector<CxxString>>>;

        /// Computes the closure of a list of valid paths.
        ///
        /// This is the multi-path variant of `compute_fs_closure`.
        /// If `flip_directions` is true, the set of paths that can reach `store_path` is
        /// returned.
        ///
        /// It's easier and more efficient to just pass a vector of slices
        /// instead of wrangling with concrete "extern rust" / "extern C++"
        /// types.
        fn compute_fs_closure_multi(
            self: Pin<&mut CNixStore>,
            base_names: &[&[u8]],
            flip_direction: bool,
            include_outputs: bool,
            include_derivers: bool,
        ) -> Result<UniquePtr<CxxVector<CxxString>>>;

        /// Creates a NAR dump from a path.
        fn nar_from_path(
            self: Pin<&mut CNixStore>,
            base_name: Vec<u8>,
            sender: Box<AsyncWriteSender>,
        ) -> Result<()>;

        /// Obtains a handle to the Nix store.
        fn open_nix_store() -> Result<UniquePtr<CNixStore>>;

        // =========
        // CPathInfo
        // =========

        /// Mid-level wrapper for the `nix::ValidPathInfo` struct.
        type CPathInfo;

        /// Returns the SHA-256 hash of the store path.
        fn nar_sha256_hash(self: Pin<&mut CPathInfo>) -> &[u8];

        /// Returns the size of the NAR.
        fn nar_size(self: Pin<&mut CPathInfo>) -> u64;

        /// Returns the references of the store path.
        fn references(self: Pin<&mut CPathInfo>) -> UniquePtr<CxxVector<CxxString>>;

        /// Returns the possibly invalid signatures attached to the store path.
        fn sigs(self: Pin<&mut CPathInfo>) -> UniquePtr<CxxVector<CxxString>>;

        /// Returns the CA field of the store path.
        fn ca(self: Pin<&mut CPathInfo>) -> String;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn paused_consumer_applies_backpressure_and_drop_releases_producer() {
        let (adapter, mut sender) = AsyncWriteAdapter::new();
        let (finished, mut completion) = tokio::sync::oneshot::channel();
        let producer = tokio::task::spawn_blocking(move || {
            let block = vec![42; 64 * 1024];
            for _ in 0..256 {
                if sender.send(&block).is_err() {
                    return;
                }
            }
            let _ = finished.send(());
        });
        let result = tokio::time::timeout(Duration::from_millis(200), &mut completion).await;
        drop(adapter);
        tokio::time::timeout(Duration::from_secs(5), producer)
            .await
            .expect("producer remained blocked after receiver drop")
            .unwrap();
        assert!(
            result.is_err(),
            "producer buffered the entire paused stream"
        );
    }

    #[tokio::test]
    async fn small_writes_are_coalesced_and_eof_flushes_remainder() {
        let (mut adapter, mut sender) = AsyncWriteAdapter::new();
        let producer = tokio::task::spawn_blocking(move || {
            for _ in 0..(64 * 1024 + 17) {
                sender.send(b"x").unwrap();
            }
            sender.eof().unwrap();
        });
        let full = adapter.next().await.unwrap().unwrap();
        assert_eq!(full.len(), 64 * 1024);
        assert!(full.iter().all(|byte| *byte == b'x'));
        let remainder = adapter.next().await.unwrap().unwrap();
        assert_eq!(remainder.len(), 17);
        assert!(remainder.iter().all(|byte| *byte == b'x'));
        assert!(adapter.next().await.is_none());
        producer.await.unwrap();
    }

    #[tokio::test]
    async fn stream_preserves_data_and_completes_at_eof() {
        let (mut adapter, mut sender) = AsyncWriteAdapter::new();
        let producer = tokio::task::spawn_blocking(move || {
            sender.send(b"first").unwrap();
            sender.send(b"second").unwrap();
            sender.eof().unwrap();
        });
        let mut bytes = Vec::new();
        while let Some(block) = adapter.next().await {
            bytes.extend(block.unwrap());
        }
        assert_eq!(bytes, b"firstsecond");
        assert!(adapter.next().await.is_none());
        producer.await.unwrap();
    }

    #[tokio::test]
    async fn stream_propagates_serializer_error() {
        let (mut adapter, mut sender) = AsyncWriteAdapter::new();
        let producer = tokio::task::spawn_blocking(move || {
            sender.send(b"unfinished").unwrap();
            sender
                .rust_error(io::Error::other("serialization failed"))
                .unwrap();
        });
        let error = adapter.next().await.unwrap().unwrap_err();
        assert!(error.to_string().contains("serialization failed"));
        producer.await.unwrap();
    }
}
