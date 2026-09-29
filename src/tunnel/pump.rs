//! Moves one tunnel stream between a local socket and its K connections.
//!
//! Outbound, one task reads the local socket, numbers each read as a frame
//! (`seq`), and queues it; K writer tasks take frames from the queue in
//! order, each sealing with its own connection's key and counter. A writer
//! only takes a frame when its socket accepted the last one, so a slow
//! connection simply carries fewer frames.
//!
//! Inbound, K reader tasks open frames and hand them to a [`Reorder`]
//! buffer, and one task writes them to the local socket in `seq` order.
//! The buffer holds at most `limit` bytes, except that the frame the local
//! writer waits for is always taken. Each connection carries increasing
//! `seq`s, so the connection with that frame never has a reader stuck on a
//! later one, and a full buffer can never deadlock the stream; it stops
//! reading the connections that are ahead, and TCP pushes back on the
//! sender.
//!
//! A `Fin` frame ends one direction. The stream ends cleanly when both
//! directions have ended; any error, or every connection closing before the
//! peer's `Fin`, aborts it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinSet;

use super::proto::{
    Dir, FRAME_HEADER_LEN, FRAME_MAX, FrameHeader, FrameKind, frame_aad, stream_key,
};
use crate::crypto::{Cipher, FrameKey, SessionKeys, TAG_LEN};

/// Each connection's keys for one stream, both directions.
pub(crate) struct StreamCrypto {
    session_id: [u8; 16],
    send: Vec<FrameKey>,
    recv: Vec<FrameKey>,
}

impl StreamCrypto {
    pub(crate) fn new(
        keys: &SessionKeys,
        cipher: Cipher,
        stream: u32,
        conns: u32,
        client: bool,
    ) -> Self {
        let (out, back) = if client {
            (Dir::ClientToServer, Dir::ServerToClient)
        } else {
            (Dir::ServerToClient, Dir::ClientToServer)
        };
        let keys_for = |dir| {
            (0..conns)
                .map(|i| FrameKey::new(cipher, &stream_key(keys, stream, i, dir)))
                .collect()
        };
        StreamCrypto {
            session_id: keys.session_id,
            send: keys_for(out),
            recv: keys_for(back),
        }
    }
}

/// Plaintext bytes moved each way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub sent: u64,
    pub received: u64,
}

/// Pumps a local TCP socket. Unless the stream ends cleanly (it fails, or
/// its task is cancelled because the session ended), the local socket is
/// reset rather than closed, so the application sees an error instead of an
/// end of stream that would pass a cut-off download as complete.
pub(crate) async fn pump_tcp(
    local: TcpStream,
    conns: Vec<TcpStream>,
    crypto: StreamCrypto,
) -> Result<Traffic> {
    let _ = local.set_nodelay(true);
    let mut guard = ResetGuard::new(&local);
    let (r, w) = tokio::io::split(local);
    let result = pump(r, w, conns, crypto).await;
    if result.is_ok() {
        guard.disarm();
    }
    result
}

/// Resets a socket when dropped, unless disarmed. It holds a second handle
/// to the socket, so the socket stays open until the linger choice is made
/// whatever else drops first; `tokio::io::split` halves, unlike
/// `into_split` ones, do not shut the socket down when dropped.
pub(crate) struct ResetGuard(Option<socket2::Socket>);

impl ResetGuard {
    pub(crate) fn new(socket: &TcpStream) -> Self {
        ResetGuard(SockRef::from(socket).try_clone().ok())
    }

    pub(crate) fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ResetGuard {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            let _ = handle.set_linger(Some(Duration::ZERO));
        }
    }
}

/// What finished.
enum Done {
    LocalRead(u64),
    ConnWrite,
    ConnRead,
    LocalWrite(u64),
}

/// A frame read from the local side, `FRAME_HEADER_LEN` bytes of header
/// space, the plaintext, and `TAG_LEN` bytes of tag space.
struct Outgoing {
    seq: u64,
    kind: FrameKind,
    buf: Vec<u8>,
}

pub(crate) async fn pump<R, W>(
    local_r: R,
    local_w: W,
    conns: Vec<TcpStream>,
    crypto: StreamCrypto,
) -> Result<Traffic>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let k = conns.len();
    assert!(k > 0 && k == crypto.send.len() && k == crypto.recv.len());
    let (tx, rx) = mpsc::channel::<Outgoing>(2 * k);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let reorder = Arc::new(Reorder::new(k, reorder_limit(k)));
    let sid = crypto.session_id;
    let mut tasks = JoinSet::new();
    tasks.spawn(read_local(local_r, tx));
    for ((conn, send), recv) in conns.into_iter().zip(crypto.send).zip(crypto.recv) {
        let _ = conn.set_nodelay(true);
        let (r, w) = conn.into_split();
        tasks.spawn(write_conn(w, rx.clone(), send, sid));
        tasks.spawn(read_conn(r, reorder.clone(), recv, sid));
    }
    tasks.spawn(write_local(local_w, reorder));
    let mut traffic = Traffic::default();
    let (mut outbound_left, mut inbound_done) = (1 + k, false);
    while let Some(joined) = tasks.join_next().await {
        match joined.map_err(|e| anyhow!("stream task failed: {e}"))?? {
            Done::LocalRead(n) => {
                traffic.sent = n;
                outbound_left -= 1;
            }
            Done::ConnWrite => outbound_left -= 1,
            Done::ConnRead => {}
            Done::LocalWrite(n) => {
                traffic.received = n;
                inbound_done = true;
            }
        }
        // Readers still waiting for their connection's end are dropped: the
        // peer has nothing left to send.
        if outbound_left == 0 && inbound_done {
            break;
        }
    }
    Ok(traffic)
}

/// Out-of-order bytes a stream over `k` connections may hold.
fn reorder_limit(k: usize) -> usize {
    ((k + 1) * (2 << 20)).min(64 << 20)
}

async fn read_local<R: AsyncRead + Unpin>(
    mut local: R,
    tx: mpsc::Sender<Outgoing>,
) -> Result<Done> {
    let mut sent = 0u64;
    for seq in 0u64.. {
        let mut buf = vec![0u8; FRAME_HEADER_LEN + FRAME_MAX + TAG_LEN];
        let n = local
            .read(&mut buf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + FRAME_MAX])
            .await
            .context("reading the local connection")?;
        let kind = if n == 0 {
            FrameKind::Fin
        } else {
            FrameKind::Data
        };
        buf.truncate(FRAME_HEADER_LEN + n + TAG_LEN);
        tx.send(Outgoing { seq, kind, buf })
            .await
            .map_err(|_| anyhow!("every stream connection failed"))?;
        if n == 0 {
            break;
        }
        sent += n as u64;
    }
    Ok(Done::LocalRead(sent))
}

async fn write_conn(
    mut w: OwnedWriteHalf,
    queue: Arc<tokio::sync::Mutex<mpsc::Receiver<Outgoing>>>,
    key: FrameKey,
    sid: [u8; 16],
) -> Result<Done> {
    for k in 0u64.. {
        // Holding the lock while waiting keeps the queue strictly FIFO across
        // writers, so each connection carries increasing seqs.
        let next = queue.lock().await.recv().await;
        let Some(Outgoing { seq, kind, mut buf }) = next else {
            break;
        };
        let header = FrameHeader {
            seq,
            kind,
            ct_len: (buf.len() - FRAME_HEADER_LEN) as u32,
        }
        .encode();
        buf[..FRAME_HEADER_LEN].copy_from_slice(&header);
        key.seal(k, &frame_aad(&sid, &header), &mut buf[FRAME_HEADER_LEN..])?;
        w.write_all(&buf)
            .await
            .context("writing a stream connection")?;
    }
    w.shutdown().await.context("closing a stream connection")?;
    Ok(Done::ConnWrite)
}

async fn read_conn(
    r: OwnedReadHalf,
    reorder: Arc<Reorder>,
    key: FrameKey,
    sid: [u8; 16],
) -> Result<Done> {
    let mut r = BufReader::with_capacity(4 * (FRAME_HEADER_LEN + FRAME_MAX + TAG_LEN), r);
    for k in 0u64.. {
        let mut header = [0u8; FRAME_HEADER_LEN];
        if !read_header(&mut r, &mut header).await? {
            reorder.conn_closed();
            return Ok(Done::ConnRead);
        }
        let h = FrameHeader::decode(&header)?;
        let mut body = vec![0u8; h.ct_len as usize];
        r.read_exact(&mut body)
            .await
            .context("stream connection closed mid-frame")?;
        key.open(k, &frame_aad(&sid, &header), &mut body)
            .context("stream frame failed to authenticate")?;
        body.truncate(body.len() - TAG_LEN);
        let frame = match h.kind {
            FrameKind::Data => Frame::Data(body),
            FrameKind::Fin => Frame::Fin,
        };
        reorder.push(h.seq, frame).await?;
    }
    unreachable!("u64 frame counter exhausted")
}

/// Reads a whole header; `false` on a clean end of stream before its first
/// byte.
async fn read_header<R: AsyncRead + Unpin>(r: &mut R, header: &mut [u8]) -> Result<bool> {
    let mut filled = 0;
    while filled < header.len() {
        match r.read(&mut header[filled..]).await? {
            0 if filled == 0 => return Ok(false),
            0 => bail!("stream connection closed mid-header"),
            n => filled += n,
        }
    }
    Ok(true)
}

async fn write_local<W: AsyncWrite + Unpin>(mut local: W, reorder: Arc<Reorder>) -> Result<Done> {
    let mut received = 0u64;
    loop {
        match reorder.pop().await? {
            Frame::Data(bytes) => {
                local
                    .write_all(&bytes)
                    .await
                    .context("writing the local connection")?;
                local.flush().await?;
                received += bytes.len() as u64;
            }
            Frame::Fin => {
                local
                    .shutdown()
                    .await
                    .context("closing the local connection")?;
                return Ok(Done::LocalWrite(received));
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    Data(Vec<u8>),
    Fin,
}

impl Frame {
    /// Bytes a frame counts for against the limit; a floor keeps a flood of
    /// tiny frames bounded too.
    fn cost(&self) -> usize {
        match self {
            Frame::Data(b) => b.len().max(4096),
            Frame::Fin => 4096,
        }
    }
}

/// Puts frames from K connections back in `seq` order, holding at most
/// `limit` bytes (plus the frame that is next).
pub(crate) struct Reorder {
    state: Mutex<ReorderState>,
    changed: Notify,
    limit: usize,
}

struct ReorderState {
    next: u64,
    pending: BTreeMap<u64, Frame>,
    held: usize,
    /// Connections that have not reached their end.
    open: usize,
    fin: Option<u64>,
}

impl Reorder {
    pub(crate) fn new(conns: usize, limit: usize) -> Self {
        Reorder {
            state: Mutex::new(ReorderState {
                next: 0,
                pending: BTreeMap::new(),
                held: 0,
                open: conns,
                fin: None,
            }),
            changed: Notify::new(),
            limit,
        }
    }

    /// Adds a frame, waiting while the buffer is full unless this is the
    /// frame the writer needs next.
    pub(crate) async fn push(&self, seq: u64, frame: Frame) -> Result<()> {
        let cost = frame.cost();
        let mut frame = Some(frame);
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut s = self.state.lock().unwrap();
                ensure!(
                    seq >= s.next && !s.pending.contains_key(&seq),
                    "stream frame {seq} arrived twice"
                );
                ensure!(
                    s.fin.is_none_or(|fin| seq < fin),
                    "stream frame {seq} came after the end"
                );
                if seq == s.next || s.held + cost <= self.limit {
                    let frame = frame.take().unwrap();
                    if frame == Frame::Fin {
                        ensure!(
                            s.pending.keys().next_back().is_none_or(|&last| last < seq),
                            "stream frames came after the end"
                        );
                        s.fin = Some(seq);
                    }
                    s.held += cost;
                    s.pending.insert(seq, frame);
                    drop(s);
                    self.changed.notify_waiters();
                    return Ok(());
                }
            }
            changed.await;
        }
    }

    /// The next frame in order. Fails once every connection has ended
    /// without delivering it: the peer aborted the stream.
    pub(crate) async fn pop(&self) -> Result<Frame> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut s = self.state.lock().unwrap();
                let next = s.next;
                if let Some(frame) = s.pending.remove(&next) {
                    s.next += 1;
                    s.held -= frame.cost();
                    drop(s);
                    self.changed.notify_waiters();
                    return Ok(frame);
                }
                if s.open == 0 {
                    bail!("the peer aborted the stream");
                }
            }
            changed.await;
        }
    }

    pub(crate) fn conn_closed(&self) {
        self.state.lock().unwrap().open -= 1;
        self.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    fn data(n: u8) -> Frame {
        Frame::Data(vec![n; 10])
    }

    #[tokio::test]
    async fn reorder_delivers_in_seq_order() {
        let r = Reorder::new(2, 1 << 20);
        for seq in [2, 0, 3, 1] {
            r.push(seq, data(seq as u8)).await.unwrap();
        }
        r.push(4, Frame::Fin).await.unwrap();
        for seq in 0..4 {
            assert_eq!(r.pop().await.unwrap(), data(seq));
        }
        assert_eq!(r.pop().await.unwrap(), Frame::Fin);
    }

    #[tokio::test]
    async fn reorder_rejects_duplicates_and_frames_past_the_end() {
        let r = Reorder::new(1, 1 << 20);
        r.push(1, data(1)).await.unwrap();
        assert!(r.push(1, data(1)).await.is_err());
        r.push(0, data(0)).await.unwrap();
        r.pop().await.unwrap();
        assert!(r.push(0, data(0)).await.is_err());
        r.push(3, Frame::Fin).await.unwrap();
        assert!(r.push(4, data(4)).await.is_err());
        let r = Reorder::new(1, 1 << 20);
        r.push(5, data(5)).await.unwrap();
        assert!(r.push(4, Frame::Fin).await.is_err());
    }

    #[tokio::test]
    async fn a_full_buffer_waits_but_always_takes_the_next_frame() {
        let r = Arc::new(Reorder::new(2, 8192));
        r.push(1, data(1)).await.unwrap();
        r.push(2, data(2)).await.unwrap();
        // Full: frame 3 must wait for room.
        let waiting = tokio::spawn({
            let r = r.clone();
            async move { r.push(3, data(3)).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished());
        // Frame 0 is next, so it goes in over the limit.
        timeout(Duration::from_secs(1), r.push(0, data(0)))
            .await
            .unwrap()
            .unwrap();
        for seq in 0..4 {
            assert_eq!(r.pop().await.unwrap(), data(seq));
        }
        waiting.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn every_connection_ending_without_fin_is_an_abort() {
        let r = Reorder::new(2, 1 << 20);
        r.push(0, data(0)).await.unwrap();
        r.push(2, data(2)).await.unwrap();
        r.conn_closed();
        r.conn_closed();
        assert_eq!(r.pop().await.unwrap(), data(0));
        let err = r.pop().await.unwrap_err();
        assert!(err.to_string().contains("aborted"), "{err}");
    }

    /// K connected socket pairs, as the two ends of a stream's connections.
    async fn socket_pairs(k: usize) -> (Vec<TcpStream>, Vec<TcpStream>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for _ in 0..k {
            let (c, s) = tokio::join!(TcpStream::connect(addr), listener.accept());
            a.push(c.unwrap());
            b.push(s.unwrap().0);
        }
        (a, b)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stream_striped_over_many_connections_arrives_intact_both_ways() {
        let keys = SessionKeys::derive(&[1u8; 32], &[2u8; 32]);
        for k in [1u32, 3, 8] {
            let (a, b) = socket_pairs(k as usize).await;
            let (app_a, pump_a) = tokio::io::duplex(1 << 16);
            let (app_b, pump_b) = tokio::io::duplex(1 << 16);
            let crypto_a = StreamCrypto::new(&keys, Cipher::Aes256Gcm, 9, k, true);
            let crypto_b = StreamCrypto::new(&keys, Cipher::Aes256Gcm, 9, k, false);
            let (ra, wa) = tokio::io::split(pump_a);
            let (rb, wb) = tokio::io::split(pump_b);
            let side_a = tokio::spawn(pump(ra, wa, a, crypto_a));
            let side_b = tokio::spawn(pump(rb, wb, b, crypto_b));
            let up: Vec<u8> = (0..(5 << 20) + 17)
                .map(|i: u32| (i * 7 % 251) as u8)
                .collect();
            let down: Vec<u8> = (0..(3 << 20) + 5)
                .map(|i: u32| (i * 13 % 241) as u8)
                .collect();
            let exchange = |app: tokio::io::DuplexStream, out: Vec<u8>| async move {
                let (mut r, mut w) = tokio::io::split(app);
                let writer = async move {
                    w.write_all(&out).await.unwrap();
                    w.shutdown().await.unwrap();
                };
                let reader = async move {
                    let mut got = Vec::new();
                    r.read_to_end(&mut got).await.unwrap();
                    got
                };
                tokio::join!(writer, reader).1
            };
            let (got_b, got_a) =
                tokio::join!(exchange(app_a, up.clone()), exchange(app_b, down.clone()));
            assert_eq!(got_a, up, "k = {k}");
            assert_eq!(got_b, down, "k = {k}");
            let ta = side_a.await.unwrap().unwrap();
            let tb = side_b.await.unwrap().unwrap();
            assert_eq!((ta.sent, ta.received), (up.len() as u64, down.len() as u64));
            assert_eq!((tb.sent, tb.received), (down.len() as u64, up.len() as u64));
        }
    }

    #[tokio::test]
    async fn a_peer_that_drops_its_connections_aborts_the_stream() {
        let keys = SessionKeys::derive(&[1u8; 32], &[2u8; 32]);
        let (a, b) = socket_pairs(2).await;
        let (app, pump_end) = tokio::io::duplex(1 << 16);
        let (r, w) = tokio::io::split(pump_end);
        let side = tokio::spawn(pump(
            r,
            w,
            a,
            StreamCrypto::new(&keys, Cipher::Aes256Gcm, 1, 2, true),
        ));
        drop(b);
        let err = timeout(Duration::from_secs(5), side)
            .await
            .unwrap()
            .unwrap();
        assert!(err.is_err());
        drop(app);
    }
}
