//! Shared bounded DATA sending for TCP and IP streams.
use bytes::Bytes;
use h2::SendStream;
use std::{
    future::poll_fn,
    io,
    task::{Context, Poll},
};

pub(crate) fn poll_capacity(
    output: &mut SendStream<Bytes>,
    cx: &mut Context<'_>,
    wanted: usize,
) -> Poll<io::Result<usize>> {
    output.reserve_capacity(wanted);
    loop {
        match std::task::ready!(output.poll_capacity(cx)) {
            Some(Ok(0)) => continue,
            Some(Ok(n)) => return Poll::Ready(Ok(n.min(wanted))),
            Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "H2 stream closed",
                )));
            }
        }
    }
}

pub(crate) async fn send(output: &mut SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        let wanted = data.len().min(crate::CHUNK);
        let n = poll_fn(|cx| poll_capacity(output, cx, wanted)).await?;
        output
            .send_data(data.split_to(n), false)
            .map_err(io::Error::other)?;
    }
    Ok(())
}
