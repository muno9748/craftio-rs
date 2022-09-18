#[cfg(feature = "encryption")]
use crate::cfb8::{setup_craft_cipher, CipherError, CraftCipher};
use crate::util::get_sized_buf;
use crate::wrapper::{CraftIo, CraftWrapper};
#[cfg(feature = "compression")]
use flate2::{DecompressError, FlushDecompress, Status};
use mcproto_rs::protocol::{Id, PacketDirection, RawPacket, State};
#[cfg(feature = "gat")]
use mcproto_rs::protocol::PacketKind;
use mcproto_rs::types::VarInt;
use mcproto_rs::{Deserialize, Deserialized};
#[cfg(feature = "backtrace")]
use std::backtrace::Backtrace;
use std::io;
use thiserror::Error;
#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
use async_trait::async_trait;

pub const DEAFULT_MAX_PACKET_SIZE: usize = 32 * 1000 * 1000; // 32MB

#[derive(Debug, Error)]
pub enum ReadError {
    #[error("i/o failure during read")]
    IoFailure {
        #[from]
        err: io::Error,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[error("failed to read header VarInt")]
    PacketHeaderErr {
        #[from]
        err: mcproto_rs::DeserializeErr,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[error("failed to read packet")]
    PacketErr {
        #[from]
        err: mcproto_rs::protocol::PacketErr,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[cfg(feature = "compression")]
    #[error("failed to decompress packet")]
    DecompressFailed {
        #[from]
        err: DecompressErr,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[error("{size} exceeds max size of {max_size}")]
    PacketTooLarge {
        size: usize,
        max_size: usize,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    }
}

#[cfg(feature = "compression")]
#[derive(Debug, Error)]
pub enum DecompressErr {
    #[error("buf error")]
    BufError,
    #[error("failure while decompressing")]
    Failure(#[from] DecompressError),
}

pub type ReadResult<P> = Result<Option<P>, ReadError>;

#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
#[async_trait]
pub trait CraftAsyncReader {
    #[cfg(not(feature = "gat"))]
    async fn read_packet_async<'a, P>(&'a mut self) -> ReadResult<<P as RawPacket<'a>>::Packet>
    where
        P: RawPacket<'a>,
    {
        deserialize_raw_packet(self.read_raw_packet_async::<P>().await)
    }

    #[cfg(feature = "gat")]
    async fn read_packet_async<P>(&mut self) -> ReadResult<<P::RawPacket<'_> as RawPacket<'_>>::Packet>
    where
        P: PacketKind
    {
        deserialize_raw_packet(self.read_raw_packet_async::<P>().await)
    }

    #[cfg(not(feature = "gat"))]
    async fn read_raw_packet_async<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>;

    #[cfg(feature = "gat")]
    async fn read_raw_packet_async<P>(&mut self) -> ReadResult<P::RawPacket<'_>>
    where
        P: PacketKind;

    async fn read_raw_untyped_packet_async(&mut self) -> ReadResult<(Id, &[u8])>;
}

pub trait CraftSyncReader {
    #[cfg(not(feature = "gat"))]
    fn read_packet<'a, P>(&'a mut self) -> ReadResult<<P as RawPacket<'a>>::Packet>
    where
        P: RawPacket<'a>,
    {
        deserialize_raw_packet(self.read_raw_packet::<'a, P>())
    }

    #[cfg(feature = "gat")]
    fn read_packet<P>(&mut self) -> ReadResult<<P::RawPacket<'_> as RawPacket>::Packet>
    where
        P: PacketKind
    {
        deserialize_raw_packet(self.read_raw_packet::<P>())
    }

    #[cfg(not(feature = "gat"))]
    fn read_raw_packet<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>;

    #[cfg(feature = "gat")]
    fn read_raw_packet<P>(&mut self) -> ReadResult<P::RawPacket<'_>>
    where
        P: PacketKind;

    fn read_raw_untyped_packet(&mut self) -> ReadResult<(Id, &[u8])>;
}

///
/// Wraps some stream of type `R`, and implements either `CraftSyncReader` or `CraftAsyncReader` (or both)
/// based on what types `R` implements.
///
/// You can construct this type calling the function `wrap_with_state`, which requires you to specify
/// a packet direction (are written packets server-bound or client-bound?) and a state
/// (`handshaking`? `login`? `status`? `play`?).
///
/// This type holds some internal buffers but only allocates them when they are required.
///
pub struct CraftReader<R> {
    inner: R,
    raw_buf: Option<Vec<u8>>,
    raw_ready: usize,
    raw_offset: usize,
    max_packet_size: usize,
    #[cfg(feature = "compression")]
    decompress_buf: Option<Vec<u8>>,
    #[cfg(feature = "compression")]
    compression_threshold: Option<i32>,
    state: State,
    direction: PacketDirection,
    #[cfg(feature = "encryption")]
    encryption: Option<CraftCipher>,
}

impl<R> CraftWrapper<R> for CraftReader<R> {
    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R> CraftIo for CraftReader<R> {
    fn set_state(&mut self, next: State) {
        self.state = next;
    }

    #[cfg(feature = "compression")]
    fn set_compression_threshold(&mut self, threshold: Option<i32>) {
        self.compression_threshold = threshold;
    }

    #[cfg(feature = "encryption")]
    fn enable_encryption(&mut self, key: &[u8], iv: &[u8]) -> Result<(), CipherError> {
        setup_craft_cipher(&mut self.encryption, key, iv, false)
    }

    fn set_max_packet_size(&mut self, max_size: usize) {
        debug_assert!(max_size > 5);
        self.max_packet_size = max_size;
    }

    fn ensure_buf_capacity(&mut self, capacity: usize) {
        let alloc_to = if capacity > self.max_packet_size {
            self.max_packet_size
        } else {
            capacity
        };
        self.move_ready_data_to_front();
        get_sized_buf(&mut self.raw_buf, 0, alloc_to);
    }

    #[cfg(feature = "compression")]
    fn ensure_compression_buf_capacity(&mut self, capacity: usize) {
        let alloc_to = if capacity > self.max_packet_size {
            self.max_packet_size
        } else {
            capacity
        };
        get_sized_buf(&mut self.decompress_buf, 0, alloc_to);
    }
}

macro_rules! rr_unwrap {
    ($result: expr) => {
        match $result {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(None),
            Err(err) => return Err(err),
        }
    };
}

macro_rules! check_unexpected_eof {
    ($result: expr) => {
        if let Err(err) = $result {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }

            return Err(err.into());
        }
    };
}

impl<R> CraftSyncReader for CraftReader<R>
where
    R: io::Read,
{
    #[cfg(not(feature = "gat"))]
    fn read_raw_packet<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>,
    {
        self.read_raw_packet_inner::<P>()
    }

    #[cfg(feature = "gat")]
    fn read_raw_packet<P>(&mut self) -> ReadResult<P::RawPacket<'_>>
    where
        P: PacketKind
    {
        self.read_raw_packet_inner::<P::RawPacket<'_>>()
    }

    fn read_raw_untyped_packet(&mut self) -> ReadResult<(Id, &[u8])> {
        self.read_untyped_packet_inner()
    }
}

#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
#[async_trait]
impl<R> CraftAsyncReader for CraftReader<R>
where
    R: AsyncReadExact,
{
    #[cfg(not(feature = "gat"))]
    async fn read_raw_packet_async<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>,
    {
        self.read_raw_packet_inner_async().await
    }

    #[cfg(feature = "gat")]
    async fn read_raw_packet_async<P>(&mut self) -> ReadResult<P::RawPacket<'_>>
    where
        P: PacketKind,
    {
        self.read_raw_packet_inner_async::<P::RawPacket<'_>>().await
    }

    async fn read_raw_untyped_packet_async(&mut self) -> ReadResult<(Id, &[u8])> {
        self.read_raw_untyped_packet_inner_async().await
    }
}

impl<R> CraftReader<R>
where
    R: io::Read,
{
    fn read_untyped_packet_inner(&mut self) -> ReadResult<(Id, &[u8])> {
        if let Some(primary_packet_len) = self.read_raw_inner()? {
            self.read_untyped_packet_in_buf(primary_packet_len)
        } else {
            Ok(None)
        }
    }

    fn read_raw_packet_inner<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>
    {
        if let Some(primary_packet_len) = self.read_raw_inner()? {
            self.read_packet_in_buf(primary_packet_len)
        } else {
            Ok(None)
        }
    }

    fn read_raw_inner(&mut self) -> ReadResult<usize> {
        self.move_ready_data_to_front();
        
        let primary_packet_len = rr_unwrap!(self.read_packet_len_sync()).0 as usize;
        if primary_packet_len > self.max_packet_size {
            return Err(ReadError::PacketTooLarge {
                size: primary_packet_len,
                max_size: self.max_packet_size,
                #[cfg(feature="backtrace")]
                backtrace: Backtrace::capture(),
            });
        }

        if self.ensure_n_ready_sync(primary_packet_len)?.is_none() {
            return Ok(None);
        }

        Ok(Some(primary_packet_len))
    }

    fn read_packet_len_sync(&mut self) -> ReadResult<VarInt> {
        let mut position: usize = 0;
        let mut value: i32 = 0;

        loop {
            let byte = &mut [rr_unwrap!(self.read_byte_sync())[0]];

            #[cfg(feature = "encryption")]
            handle_decryption(self.encryption.as_mut(), byte);

            let byte = byte[0];

            value |= ((byte & 0x7F) as i32) << (position * 7);

            position += 1;

            self.raw_ready -= 1;
            self.raw_offset += 1;

            if byte & 0x80 == 0 {
                break Ok(Some(value.into()));
            }

            if position > 4 {
                panic!("VarInt too long");
            }
        }
    }

    fn read_byte_sync(&mut self) -> ReadResult<&mut [u8]> {
        if self.raw_ready < 1 {
            let target =
                get_sized_buf(&mut self.raw_buf, self.raw_offset, 1);
            debug_assert_eq!(target.len(), 1);
            check_unexpected_eof!(self.inner.read_exact(target));
            self.raw_ready = 1;
        }

        let ready = get_sized_buf(&mut self.raw_buf, self.raw_offset, 1);
        debug_assert_eq!(ready.len(), 1);

        Ok(Some(ready))
    }

    fn ensure_n_ready_sync(&mut self, n: usize) -> ReadResult<&[u8]> {
        if self.raw_ready < n {
            let to_read = n - self.raw_ready;
            let target =
                get_sized_buf(&mut self.raw_buf, self.raw_offset + self.raw_ready, to_read);
            check_unexpected_eof!(self.inner.read_exact(target));
            self.raw_ready = n;
        }

        let ready = get_sized_buf(&mut self.raw_buf, self.raw_offset, n);
        Ok(Some(ready))
    }
}

#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
impl<R> CraftReader<R>
where
    R: AsyncReadExact,
{
    async fn read_raw_packet_inner_async<'a, P>(&'a mut self) -> ReadResult<P>
    where
        P: RawPacket<'a>
    {
        if let Some(primary_packet_len) = self.read_raw_inner_async().await? {
            self.read_packet_in_buf(primary_packet_len)
        } else {
            Ok(None)
        }
    }

    async fn read_raw_untyped_packet_inner_async(&mut self) -> ReadResult<(Id, &[u8])> {
        if let Some(primary_packet_len) = self.read_raw_inner_async().await? {
            self.read_untyped_packet_in_buf(primary_packet_len)
        } else {
            Ok(None)
        }
    }

    async fn read_raw_inner_async(&mut self) -> ReadResult<usize> {
        self.move_ready_data_to_front();
        
        let primary_packet_len = rr_unwrap!(self.read_packet_len_async().await).0 as usize;
        if primary_packet_len > self.max_packet_size {
            return Err(ReadError::PacketTooLarge {
                size: primary_packet_len,
                max_size: self.max_packet_size,
                #[cfg(feature="backtrace")]
                backtrace: Backtrace::capture(),
            });
        }

        if self.ensure_n_ready_async(primary_packet_len).await?.is_none() {
            return Ok(None);
        }

        debug_assert!(self.raw_ready >= primary_packet_len, "{} packet len bytes are ready (actual: {})", primary_packet_len, self.raw_ready);
        Ok(Some(primary_packet_len))
    }

    async fn read_packet_len_async(&mut self) -> ReadResult<VarInt> {
        let mut position: usize = 0;
        let mut value: i32 = 0;

        loop {
            let byte = &mut [rr_unwrap!(self.read_byte().await)[0]];

            #[cfg(feature = "encryption")]
            handle_decryption(self.encryption.as_mut(), byte);

            let byte = byte[0];

            value |= ((byte & 0x7F) as i32) << (position * 7);

            position += 1;

            self.raw_ready -= 1;
            self.raw_offset += 1;

            if byte & 0x80 == 0 {
                break Ok(Some(value.into()));
            }

            if position > 4 {
                panic!("VarInt too long");
            }
        }
    }

    async fn read_byte(&mut self) -> ReadResult<&mut [u8]> {
        if self.raw_ready < 1 {
            let target =
                get_sized_buf(&mut self.raw_buf, self.raw_offset, 1);
            debug_assert_eq!(target.len(), 1);
            check_unexpected_eof!(self.inner.read_exact(target).await);
            self.raw_ready = 1;
        }

        let ready = get_sized_buf(&mut self.raw_buf, self.raw_offset, 1);
        debug_assert_eq!(ready.len(), 1);

        Ok(Some(ready))
    }

    async fn ensure_n_ready_async(&mut self, n: usize) -> ReadResult<&mut [u8]> {
        if self.raw_ready < n {
            let to_read = n - self.raw_ready;
            let target =
                get_sized_buf(&mut self.raw_buf, self.raw_offset + self.raw_ready, to_read);
            debug_assert_eq!(target.len(), to_read);
            check_unexpected_eof!(self.inner.read_exact(target).await);
            self.raw_ready = n;
        }

        let ready = get_sized_buf(&mut self.raw_buf, self.raw_offset, n);
        debug_assert_eq!(ready.len(), n);

        Ok(Some(ready))
    }
}

#[cfg(any(feature = "futures-io", feature = "tokio-io"))]
#[async_trait]
pub trait AsyncReadExact: Unpin + Sync + Send {
    async fn read_exact(&mut self, to: &mut [u8]) -> Result<(), io::Error>;
}

#[cfg(all(feature = "futures-io", not(feature = "tokio-io")))]
#[async_trait]
impl<R> AsyncReadExact for R
where
    R: futures::AsyncReadExt + Unpin + Sync + Send,
{
    async fn read_exact(&mut self, to: &mut [u8]) -> Result<(), io::Error> {
        futures::AsyncReadExt::read_exact(self, to).await
    }
}

#[cfg(feature = "tokio-io")]
#[async_trait]
impl<R> AsyncReadExact for R
where
    R: tokio::io::AsyncRead + Unpin + Sync + Send,
{
    async fn read_exact(&mut self, to: &mut [u8]) -> Result<(), io::Error> {
        tokio::io::AsyncReadExt::read_exact(self, to).await?;
        Ok(())
    }
}

macro_rules! dsz_unwrap {
    ($bnam: expr, $k: ty) => {
        match <$k>::mc_deserialize($bnam) {
            Ok(Deserialized {
                value: val,
                data: rest,
            }) => (val, rest),
            Err(err) => {
                return Err(err.into());
            }
        }
    };
}

impl<R> CraftReader<R> {
    pub fn wrap(inner: R, direction: PacketDirection) -> Self {
        Self::wrap_with_state(inner, direction, State::Handshaking)
    }

    pub fn wrap_with_state(inner: R, direction: PacketDirection, state: State) -> Self {
        Self {
            inner,
            raw_buf: None,
            raw_ready: 0,
            raw_offset: 0,
            #[cfg(feature = "compression")]
            decompress_buf: None,
            #[cfg(feature = "compression")]
            compression_threshold: None,
            state,
            direction,
            #[cfg(feature = "encryption")]
            encryption: None,
            max_packet_size: DEAFULT_MAX_PACKET_SIZE
        }
    }

    fn read_untyped_packet_in_buf(&mut self, size: usize) -> ReadResult<(Id, &[u8])>
    {
        // find data in buf
        let offset = self.raw_offset;
        if self.raw_ready < size {
            panic!("not enough data is ready, got {} ready and {} desired ready!", self.raw_ready, size);
        }
        self.raw_ready -= size;
        self.raw_offset += size;
        let buf =
            &mut self.raw_buf.as_mut().expect("should exist right now")[offset..offset + size];

        #[cfg(feature = "encryption")]
        handle_decryption(self.encryption.as_mut(), buf);

        // try to get the packet body bytes... this boils down to:
        // * check if compression enabled,
        //    * read data len (VarInt) which isn't compressed
        //    * if data len is 0, then rest of packet is not compressed, remaining data is body
        //    * otherwise, data len is decompressed length, so prepare a decompression buf and decompress from
        //      the buffer into the decompression buffer, and return the slice of the decompression buffer
        //      which contains this packet's data
        // * if compression not enabled, then the buf contains only the packet body bytes

        #[cfg(feature = "compression")]
        let packet_buf = if let Some(_) = self.compression_threshold {
            let (data_len, rest) = dsz_unwrap!(buf, VarInt);
            let data_len = data_len.0 as usize;
            if data_len == 0 {
                rest
            } else if data_len >= self.max_packet_size {
                return Err(ReadError::PacketTooLarge {
                    size: data_len,
                    max_size: self.max_packet_size,
                    #[cfg(feature = "backtrace")]
                    backtrace: Backtrace::capture()
                })
            } else {
                decompress(rest, &mut self.decompress_buf, data_len)?
            }
        } else {
            buf
        };

        #[cfg(not(feature = "compression"))]
        let packet_buf = buf;

        let (raw_id, body_buf) = dsz_unwrap!(packet_buf, VarInt);
        let id = Id {
            id: raw_id.0,
            state: self.state.clone(),
            direction: self.direction.clone()
        };

        Ok(Some((id, body_buf)))
    }

    fn read_packet_in_buf<'a, P>(&'a mut self, size: usize) -> ReadResult<P>
    where
        P: RawPacket<'a>,
    {
        if let Some((id, body_buf)) = self.read_untyped_packet_in_buf(size)? {
            match P::create(id, body_buf) {
                Ok(raw) => Ok(Some(raw)),
                Err(err) => Err(err.into()),
            }
        } else {
            Ok(None)
        }
    }

    fn move_ready_data_to_front(&mut self) {
        // if there's data that's ready which isn't at the front of the buf, move it to the front
        if self.raw_ready > 0 && self.raw_offset > 0 {
            let raw_buf = self
                .raw_buf
                .as_mut()
                .expect("if raw_ready > 0 and raw_offset > 0 then a raw_buf should exist!");

            raw_buf.copy_within(self.raw_offset..(self.raw_offset+self.raw_ready), 0);
        }

        self.raw_offset = 0;
    }
}

#[cfg(feature = "encryption")]
fn handle_decryption(cipher: Option<&mut CraftCipher>, buf: &mut [u8]) {
    if let Some(encryption) = cipher {
        encryption.decrypt(buf);
    }
}

fn deserialize_raw_packet<'a, P>(raw: ReadResult<P>) -> ReadResult<P::Packet>
where
    P: RawPacket<'a>,
{
    match raw {
        Ok(Some(raw)) => match raw.deserialize() {
            Ok(deserialized) => Ok(Some(deserialized)),
            Err(err) => Err(err.into()),
        },
        Ok(None) => Ok(None),
        Err(err) => Err(err),
    }
}

#[cfg(feature = "compression")]
fn decompress<'a>(
    src: &'a [u8],
    target: &'a mut Option<Vec<u8>>,
    decompressed_len: usize,
) -> Result<&'a mut [u8], ReadError> {
    let mut decompress = flate2::Decompress::new(true);
    let decompress_buf = get_sized_buf(target, 0, decompressed_len);
    loop {
        match decompress.decompress(src, decompress_buf, FlushDecompress::Finish) {
            Ok(Status::StreamEnd) => break,
            Ok(Status::Ok) => {}
            Ok(Status::BufError) => return Err(DecompressErr::BufError.into()),
            Err(err) => return Err(DecompressErr::Failure(err).into()),
        }
    }

    let decompressed_size = decompress.total_out() as usize;
    Ok(&mut decompress_buf[..decompressed_size])
}
