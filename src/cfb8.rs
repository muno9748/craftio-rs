#[cfg(feature = "backtrace")]
use std::backtrace::Backtrace;
use std::slice;
use aes::{Aes128, cipher::{KeyIvInit, BlockEncryptMut, BlockDecryptMut}};
use cfb8::{Encryptor, Decryptor};
use thiserror::Error;

pub type CraftCipherResult<T> = Result<T, CipherError>;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CipherComponent {
    Key,
    Iv,
}

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("encryption is already enabled and cannot be enabled again")]
    AlreadyEnabled {
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
    #[error("bad size '{size}' for '{component:?}'")]
    BadSize {
        size: usize,
        component: CipherComponent,
        #[cfg(feature = "backtrace")]
        backtrace: Backtrace,
    },
}

impl CipherError {
    fn bad_size(component: CipherComponent, size: usize) -> Self {
        CipherError::BadSize {
            component,
            size,
            #[cfg(feature = "backtrace")]
            backtrace: Backtrace::capture(),
        }
    }

    fn already_enabled() -> Self {
        CipherError::AlreadyEnabled {
            #[cfg(feature = "backtrace")]
            backtrace: Backtrace::capture(),
        }
    }
}

const BYTES_SIZE: usize = 16;

#[derive(Debug)]
enum CipherDirection {
    Encrypt(Encryptor<Aes128>),
    Decrypt(Decryptor<Aes128>),
}

#[derive(Debug)]
pub struct CraftCipher {
    cipher: CipherDirection
}

impl CraftCipher {
    pub fn new(key: &[u8], iv: &[u8], encryption: bool) -> CraftCipherResult<Self> {
        if iv.len() != BYTES_SIZE {
            return Err(CipherError::bad_size(CipherComponent::Iv, iv.len()));
        }

        if key.len() != BYTES_SIZE {
            return Err(CipherError::bad_size(CipherComponent::Key, key.len()));
        }

        Ok(Self {
            cipher: if encryption {
                CipherDirection::Encrypt(Encryptor::<Aes128>::new_from_slices(key, iv).unwrap())
            } else {
                CipherDirection::Decrypt(Decryptor::<Aes128>::new_from_slices(key, iv).unwrap())
            },
        })
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        match &mut self.cipher {
            CipherDirection::Encrypt(cipher) => for byte in data.iter_mut() {
                cipher.encrypt_block_mut(unsafe { slice::from_raw_parts_mut(byte, 1) }.into());
            }
            _ => unreachable!(),
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        match &mut self.cipher {
            CipherDirection::Decrypt(cipher) => for byte in data.iter_mut() {
                cipher.decrypt_block_mut(unsafe { slice::from_raw_parts_mut(byte, 1) }.into());
            }
            _ => unreachable!(),
        }
    }
}

pub(crate) fn setup_craft_cipher(
    target: &mut Option<CraftCipher>,
    key: &[u8],
    iv: &[u8],
    encryption: bool,
) -> Result<(), CipherError> {
    if target.is_some() {
        Err(CipherError::already_enabled())
    } else {
        *target = Some(CraftCipher::new(key, iv, encryption)?);
        Ok(())
    }
}