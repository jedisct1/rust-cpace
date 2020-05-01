#![no_std]
#![forbid(unsafe_code)]

use core::fmt;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use getrandom::getrandom;
use hmac_sha512::{Hash, BLOCKBYTES};

pub const SESSION_ID_BYTES: usize = 16;
pub const STEP1_PACKET_BYTES: usize = 16 + 32;
pub const STEP2_PACKET_BYTES: usize = 32;
pub const SHARED_KEY_BYTES: usize = 32;

const DSI1: &str = "CPaceRistretto255-1";
const DSI2: &str = "CPaceRistretto255-1";

#[derive(Debug)]
pub enum Error {
    Overflow(&'static str),
    Random(getrandom::Error),
    InvalidPublicKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl From<getrandom::Error> for Error {
    fn from(e: getrandom::Error) -> Self {
        Error::Random(e)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SharedKeys {
    pub k1: [u8; SHARED_KEY_BYTES],
    pub k2: [u8; SHARED_KEY_BYTES],
}

#[derive(Debug, Clone)]
pub struct CPace {
    session_id: [u8; SESSION_ID_BYTES],
    p: RistrettoPoint,
    r: Scalar,
}

pub struct Step1Out {
    ctx: CPace,
    step1_packet: [u8; STEP1_PACKET_BYTES],
}

impl Step1Out {
    pub fn packet(&self) -> [u8; STEP1_PACKET_BYTES] {
        self.step1_packet
    }

    pub fn step3(&self, step2_packet: &[u8; STEP2_PACKET_BYTES]) -> Result<SharedKeys, Error> {
        self.ctx.step3(step2_packet)
    }
}

pub struct Step2Out {
    shared_keys: SharedKeys,
    step2_packet: [u8; STEP2_PACKET_BYTES],
}

impl Step2Out {
    pub fn shared_keys(&self) -> SharedKeys {
        self.shared_keys
    }

    pub fn packet(&self) -> [u8; STEP2_PACKET_BYTES] {
        self.step2_packet
    }
}

impl CPace {
    fn new<T: AsRef<[u8]>>(
        session_id: [u8; SESSION_ID_BYTES],
        password: &str,
        id_a: &str,
        id_b: &str,
        ad: Option<T>,
    ) -> Result<Self, Error> {
        if id_a.len() > 0xff || id_b.len() > 0xff {
            return Err(Error::Overflow(
                "Identifiers must be at most 255 bytes long",
            ));
        }
        let zpad = [0u8; BLOCKBYTES];
        let pad_len = zpad.len().wrapping_sub(DSI1.len() + password.len()) & (zpad.len() - 1);
        let mut st = Hash::new();
        st.update(DSI1);
        st.update(password);
        st.update(&zpad[..pad_len]);
        st.update(session_id);
        st.update([id_a.len() as u8]);
        st.update(id_a);
        st.update([id_b.len() as u8]);
        st.update(id_b);
        st.update(ad.as_ref().map(|ad| ad.as_ref()).unwrap_or_default());
        let h = st.finalize();
        let mut p = RistrettoPoint::from_uniform_bytes(&h);
        let mut r = [0u8; 64];
        getrandom(&mut r)?;
        let r = Scalar::from_bytes_mod_order_wide(&r);
        p *= r;
        Ok(CPace { session_id, p, r })
    }

    fn finalize(
        &self,
        op: RistrettoPoint,
        ya: RistrettoPoint,
        yb: RistrettoPoint,
    ) -> Result<SharedKeys, Error> {
        let p = op * self.r;
        let mut st = Hash::new();
        st.update(DSI2);
        st.update(p.compress().as_bytes());
        st.update(ya.compress().as_bytes());
        st.update(yb.compress().as_bytes());
        let h = st.finalize();
        let (mut k1, mut k2) = ([0u8; SHARED_KEY_BYTES], [0u8; SHARED_KEY_BYTES]);
        k1.copy_from_slice(&h[..SHARED_KEY_BYTES]);
        k2.copy_from_slice(&h[SHARED_KEY_BYTES..]);
        Ok(SharedKeys { k1, k2 })
    }

    pub fn step1<T: AsRef<[u8]>>(
        password: &str,
        id_a: &str,
        id_b: &str,
        ad: Option<T>,
    ) -> Result<Step1Out, Error> {
        let mut session_id = [0u8; SESSION_ID_BYTES];
        getrandom(&mut session_id)?;
        let ctx = CPace::new(session_id, password, id_a, id_b, ad)?;
        let mut step1_packet = [0u8; STEP1_PACKET_BYTES];
        step1_packet[..SESSION_ID_BYTES].copy_from_slice(&ctx.session_id);
        step1_packet[SESSION_ID_BYTES..].copy_from_slice(ctx.p.compress().as_bytes());
        Ok(Step1Out { ctx, step1_packet })
    }

    pub fn step2<T: AsRef<[u8]>>(
        step1_packet: &[u8; STEP1_PACKET_BYTES],
        password: &str,
        id_a: &str,
        id_b: &str,
        ad: Option<T>,
    ) -> Result<Step2Out, Error> {
        let mut session_id = [0u8; SESSION_ID_BYTES];
        session_id.copy_from_slice(&step1_packet[..SESSION_ID_BYTES]);
        let ya = &step1_packet[SESSION_ID_BYTES..];
        let ctx = CPace::new(session_id, password, id_a, id_b, ad)?;
        let mut step2_packet = [0u8; STEP2_PACKET_BYTES];
        step2_packet.copy_from_slice(ctx.p.compress().as_bytes());
        let ya = CompressedRistretto::from_slice(ya)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        let shared_keys = ctx.finalize(ya, ya, ctx.p)?;
        Ok(Step2Out {
            shared_keys,
            step2_packet,
        })
    }

    pub fn step3(&self, step2_packet: &[u8; STEP2_PACKET_BYTES]) -> Result<SharedKeys, Error> {
        let yb = CompressedRistretto::from_slice(step2_packet)
            .decompress()
            .ok_or(Error::InvalidPublicKey)?;
        self.finalize(yb, self.p, yb)
    }
}

#[test]
fn test_cpace() {
    let client = CPace::step1("password", "client", "server", Some("ad")).unwrap();

    let step2 = CPace::step2(&client.packet(), "password", "client", "server", Some("ad")).unwrap();

    let shared_keys = client.step3(&step2.packet()).unwrap();

    assert_eq!(shared_keys.k1, step2.shared_keys.k1);
    assert_eq!(shared_keys.k2, step2.shared_keys.k2);
}
