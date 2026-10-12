//! Bounded AsyncRead/AsyncWrite adapter for an HTTP/3 CONNECT stream.
use crate::{
    error::Result,
    h3_transport::{RecvStream, SendStream},
};
use bytes::{Buf, Bytes};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Writer {
    stream: SendStream,
    finished: bool,
}
impl Drop for Writer {
    fn drop(&mut self) {
        if !self.finished {
            self.stream.abort();
        }
    }
}
type Sending = Pin<Box<dyn Future<Output = (Writer, Result<()>)> + Send>>;
/// One CONNECT flow. Write shutdown preserves the read half; dropping an
/// unfinished flow cancels both directions. At most 16 KiB is buffered for writes.
pub struct TcpFlow {
    input: RecvStream,
    output: Option<Writer>,
    sending: Option<Sending>,
    buffered: Bytes,
    eof: bool,
    closing: bool,
    failed: bool,
    _client: crate::h3_client::Client,
}
impl TcpFlow {
    pub(crate) fn new(
        stream: crate::h3_transport::Stream,
        client: crate::h3_client::Client,
    ) -> Self {
        let (output, input) = stream.split();
        Self {
            input,
            output: Some(Writer {
                stream: output,
                finished: false,
            }),
            sending: None,
            buffered: Bytes::new(),
            eof: false,
            closing: false,
            failed: false,
            _client: client,
        }
    }
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Some(sending) = &mut self.sending {
            let (writer, result) = std::task::ready!(sending.as_mut().poll(cx));
            self.sending = None;
            self.output = Some(writer);
            if let Err(error) = result {
                self.failed = true;
                return Poll::Ready(Err(io::Error::other(error)));
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for TcpFlow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.buffered.is_empty() {
                let size = self.buffered.len().min(buf.remaining());
                buf.put_slice(&self.buffered[..size]);
                self.buffered.advance(size);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.input.poll_recv(cx)).map_err(io::Error::other)? {
                Some(data) => self.buffered = data,
                None => self.eof = true,
            }
        }
    }
}
impl AsyncWrite for TcpFlow {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        std::task::ready!(self.poll_pending(cx))?;
        let size = data.len().min(16 * 1024);
        if size == 0 {
            return Poll::Ready(Ok(0));
        }
        let data = Bytes::copy_from_slice(&data[..size]);
        let mut writer = self.output.take().unwrap();
        self.sending = Some(Box::pin(async move {
            let result = writer.stream.send(data).await;
            (writer, result)
        }));
        Poll::Ready(Ok(size))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_pending(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_pending(cx))?;
        if !self.closing {
            self.closing = true;
            let mut writer = self.output.take().unwrap();
            self.sending = Some(Box::pin(async move {
                let result = writer.stream.finish().await;
                writer.finished = result.is_ok();
                (writer, result)
            }));
        }
        self.poll_pending(cx)
    }
}
impl Drop for TcpFlow {
    fn drop(&mut self) {
        if !self.eof {
            self.input.abort();
        }
    }
}
