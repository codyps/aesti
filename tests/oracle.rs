extern crate aesti;
extern crate openssl;
extern crate hex;
extern crate fmt_extra;

#[macro_use]
extern crate index_fixed;

#[macro_use]
extern crate quickcheck;

#[derive(Clone,PartialEq,Eq,Debug,Hash)]
enum AesKind {
    K128,
    K192,
    K256,
}

impl quickcheck::Arbitrary for AesKind {
    fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
        g.choose(&[AesKind::K128, AesKind::K192, AesKind::K256]).unwrap().clone()
    }

    // TODO: try the other AesKinds?
    /*
    fn shrink(&self) -> Box<Iterator<Item=Self>> {
    }
    */
}

fn aes_encrypt(key: &[u8], data: &[u8]) -> Vec<u8>
{
    let aes = aesti::Aes::with_key(key).unwrap();
    let mut out = vec![0;data.len()];
    aes.encrypt(index_fixed!(&mut out;..16), index_fixed!(&data;..16));
    out
}

fn aes_decrypt(key: &[u8], data: &[u8]) -> Vec<u8>
{
    let aes = aesti::Aes::with_key(key).unwrap();
    let mut out = vec![0;data.len()];
    aes.decrypt(index_fixed!(&mut out;..16), index_fixed!(&data;..16));
    out
}

fn openssl_aes_enc(key: &[u8], data: &[u8]) -> Vec<u8>
{
    let aes = openssl::aes::AesKey::new_encrypt(key).unwrap();
    let mut out = vec![0;data.len()];
    let mut iv = [0;32];
    openssl::aes::aes_ige(data, &mut out, &aes, &mut iv,  openssl::symm::Mode::Encrypt);
    out
}

fn openssl_aes_dec(key: &[u8], data: &[u8]) -> Vec<u8>
{
    let aes = openssl::aes::AesKey::new_decrypt(key).unwrap();
    let mut out = vec![0;data.len()];
    let mut iv = [0;32];
    openssl::aes::aes_ige(data, &mut out, &aes, &mut iv,  openssl::symm::Mode::Decrypt);
    out
}

quickcheck! {
    fn openssl_enc(k: AesKind, key: Vec<u8>, data: Vec<u8>) -> quickcheck::TestResult {
        let mut key = key;
        let mut data = data;

        match k {
            AesKind::K128 => key.resize(16,0),
            AesKind::K192 => key.resize(24,0),
            AesKind::K256 => key.resize(32,0),
        }

        data.resize(16, 0);

        let a = aes_encrypt(&key, &data);
        let b = openssl_aes_enc(&key, &data);
        quickcheck::TestResult::from_bool(a == b)
    }

    fn openssl_dec(k: AesKind, key: Vec<u8>, data: Vec<u8>) -> quickcheck::TestResult {
        let mut key = key;
        let mut data = data;

        match k {
            AesKind::K128 => key.resize(16,0),
            AesKind::K192 => key.resize(24,0),
            AesKind::K256 => key.resize(32,0),
        }

        data.resize(16, 0);

        let a = aes_decrypt(&key, &data);
        let b = openssl_aes_dec(&key, &data);
        quickcheck::TestResult::from_bool(a == b)
    }
}

fn vt(key: &[u8], pt: &[u8], ct: &[u8])
{
    let key: Vec<u8> = hex::FromHex::from_hex(key).unwrap();
    let pt: Vec<u8>  = hex::FromHex::from_hex(pt).unwrap();
    let ct: Vec<u8>  = hex::FromHex::from_hex(ct).unwrap();

    let cr = aes_encrypt(&key, &pt);
    assert_eq!(fmt_extra::Hs(&ct), fmt_extra::Hs(&cr));
    let pr = aes_decrypt(&key, &ct);
    assert_eq!(fmt_extra::Hs(&pt), fmt_extra::Hs(&pr));
}

macro_rules! v {
    ($name:ident, $key:expr, $pt:expr, $ct: expr) => {
        #[test]
        fn $name() {
            vt($key, $pt, $ct)
        }
    }
}

// CAVS 11.1 ECBGFSbox128 ENCRYPT 1
v!(ecb_gfs_box128_e1, b"00000000000000000000000000000000",
   b"f34481ec3cc627bacd5dc3fb08f273e6", b"0336763e966d92595a567cc9ce537f5e");

// CAVS 11.1 ECBGFSbox256 ENCRYPT 1
v!(ecb_gfs_box256_e1, b"0000000000000000000000000000000000000000000000000000000000000000",
   b"014730f80ac625fe84f026c60bfd547d", b"5c9d844ed46f9885085e5d6a4f94c7d7");
