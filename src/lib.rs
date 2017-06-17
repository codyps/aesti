/*
 * Scalar fixed time AES core transform
 *
 * Adopted to rust from linux kernel aes_ti.c by Cody P Schafer <dev@codyps.com>
 * Copyright (C) 2017 Linaro Ltd <ard.biesheuvel@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#![no_std]

/// Scalar fixed time AES core transform
/// 
/// This is a straight conversion of the aes_ti.c & aes.h code from the linux kernel.
/// 
/// *WARNING*
/// 
/// This should be used with a good mode (GCM, EME, XTS, etc). `Aes` here only implements
/// encryption/decryption of a single block. It is essentially ECB only.
/// 
/// In most cases using a complete cryptosystem library like NACL, sodium, and others will be a
/// better choice. These try to avoid various missteps that can compromise the intended use of this
/// block cipher.


#[macro_use]
extern crate index_fixed;


/*
const MIN_KEY_SIZE: usize = 16;
const MAX_KEY_SIZE: usize = 32;
*/

const KEY_SIZE_128: usize = 16;
const KEY_SIZE_192: usize = 24;
const KEY_SIZE_256: usize = 32;

//const BLOCK_SIZE: usize = 16;
const MAX_KEY_LENGTH: usize = 15 * 16;
const MAX_KEY_LENGTH_U32: usize = MAX_KEY_LENGTH / 4;

mod b {
    // In the C impl, SBOX was marked as volatile. In rust, we just need to make sure we use
    // read_volatile() to have similar behavior.
    #[inline]
    pub fn sbox_v(idx: usize) -> u8 {
	let x: *const u8 = &SBOX[idx];
	unsafe { ::core::ptr::read_volatile(x) }
    }

    #[inline]
    pub fn inv_sbox_v(idx: usize) -> u8 {
	let x: *const u8 = &INV_SBOX[idx];
	unsafe { ::core::ptr::read_volatile(x) }
    }

    /*
     * Emit the sbox as volatile const to prevent the compiler from doing
     * constant folding on sbox references involving fixed indexes.
     */
    const SBOX: [u8;256] = [
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
	];

    const INV_SBOX: [u8;256] = [
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
	0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
	0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
	0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
	0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
	0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
	0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
	0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
	0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
	0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
	0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
	0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
	0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
	0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
	0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
	0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
	0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
	];
}

use b::*;

// convenience to handle casts
#[inline]
fn sbox(idx: u32) -> u32 {
    sbox_v(idx as usize) as u32
}

#[inline]
fn inv_sbox(idx: u32) -> u32 {
    inv_sbox_v(idx as usize) as u32
}

fn mul_by_x(w: u32) -> u32
{
    let x = w & 0x7f7f7f7f;
    let y = w & 0x80808080;

    /* multiply by polynomial 'x' (0b10) in GF(2^8) */
    (x << 1) ^ (y >> 7) * 0x1b
}

fn mul_by_x2(w: u32) -> u32
{
    let x = w & 0x3f3f3f3f;
    let y = w & 0x80808080;
    let z = w & 0x40404040;

    /* multiply by polynomial 'x^2' (0b100) in GF(2^8) */
    (x << 2) ^ (y >> 7) * 0x36 ^ (z >> 6) * 0x1b
}

fn mix_columns(x: u32) -> u32
{
    /*
     * Perform the following matrix multiplication in GF(2^8)
     *
     * | 0x2 0x3 0x1 0x1 |   | x[0] |
     * | 0x1 0x2 0x3 0x1 |   | x[1] |
     * | 0x1 0x1 0x2 0x3 | x | x[2] |
     * | 0x3 0x1 0x1 0x3 |   | x[3] |
     */
    let y = mul_by_x(x) ^ x.rotate_right(16);

    y ^ (x ^ y).rotate_right(8)
}


fn inv_mix_columns(x: u32) -> u32
{
    /*
     * Perform the following matrix multiplication in GF(2^8)
     *
     * | 0xe 0xb 0xd 0x9 |   | x[0] |
     * | 0x9 0xe 0xb 0xd |   | x[1] |
     * | 0xd 0x9 0xe 0xb | x | x[2] |
     * | 0xb 0xd 0x9 0xe |   | x[3] |
     *
     * which can conveniently be reduced to
     *
     * | 0x2 0x3 0x1 0x1 |   | 0x5 0x0 0x4 0x0 |   | x[0] |
     * | 0x1 0x2 0x3 0x1 |   | 0x0 0x5 0x0 0x4 |   | x[1] |
     * | 0x1 0x1 0x2 0x3 | x | 0x4 0x0 0x5 0x0 | x | x[2] |
     * | 0x3 0x1 0x1 0x2 |   | 0x0 0x4 0x0 0x5 |   | x[3] |
     */
    let y = mul_by_x2(x);

    mix_columns(x ^ y ^ y.rotate_right(16))
}

#[inline]
fn subshift(inp: &[u32], pos: usize) -> u32
{
    sbox((inp[pos] & 0xff)) ^
	(sbox((inp[((pos + 1) % 4)] >>  8) & 0xff) <<  8) ^
	(sbox((inp[((pos + 2) % 4)] >> 16) & 0xff) << 16) ^
	(sbox((inp[((pos + 3) % 4)] >> 24) & 0xff) << 24)
}

#[inline]
fn inv_subshift(inp: &[u32;4], pos: usize) -> u32
{
    inv_sbox(inp[pos] & 0xff) ^
	(inv_sbox((inp[(pos + 3) % 4] >>  8) & 0xff) <<  8) ^
	(inv_sbox((inp[(pos + 2) % 4] >> 16) & 0xff) << 16) ^
	(inv_sbox((inp[(pos + 1) % 4] >> 24) & 0xff) << 24)
}

fn subw(inp: u32) -> u32
{
    sbox(inp & 0xff) ^
	(sbox((inp >>  8) & 0xff) <<  8) ^
	(sbox((inp >> 16) & 0xff) << 16) ^
	(sbox((inp >> 24) & 0xff) << 24)
}

fn get_unaligned_le32(x: &[u8;4]) -> u32
{
    (x[0] as u32)
	| ((x[1] as u32) << 8)
	| ((x[2] as u32) << 16)
	| ((x[3] as u32) << 24)
}

fn put_unaligned_le32(v: u32, x: &mut [u8;4])
{
    x[0] = (v >>  0) as u8;
    x[1] = (v >>  8) as u8;
    x[2] = (v >> 16) as u8;
    x[3] = (v >> 24) as u8;
}

pub struct Aes {
    key_enc: [u32;MAX_KEY_LENGTH_U32],
    key_dec: [u32;MAX_KEY_LENGTH_U32],
    key_length: usize,
}

impl Aes {
    pub fn with_key(key: &[u8]) -> Result<Self,()>
    {
	let mut x = Aes {
	    key_enc: [0;MAX_KEY_LENGTH_U32],
	    key_dec: [0;MAX_KEY_LENGTH_U32],
	    key_length: 0,
	};
	try!(x.set_key(key));
	Ok(x)
    }

    fn expand_key(&mut self, in_key: &[u8]) -> Result<(),()>
    {
	let key_len = in_key.len();
	let kwords = in_key.len() / 4;
	//u32 rc, i, j;

	if key_len != KEY_SIZE_128 && key_len != KEY_SIZE_192 && key_len != KEY_SIZE_256 {
	    return Err(());
	}

	self.key_length = in_key.len();

	for i in 0..kwords {
	    self.key_enc[i] = get_unaligned_le32(index_fixed!(&in_key[i*4..]; .. 4));
	}

	{
	    let mut i = 0;
	    let mut rc = 1;
	    loop {
		if i >= 10 {
		    break;
		}

		let (rki, rko) = self.key_enc[(i*kwords)..].split_at_mut(kwords);

		rko[0] = subw(rki[kwords - 1]).rotate_right(8) ^ rc ^ rki[0];
		rko[1] = rko[0] ^ rki[1];
		rko[2] = rko[1] ^ rki[2];
		rko[3] = rko[2] ^ rki[3];

		if key_len == 24 {
		    if i >= 7 {
			break;
		    }
		    rko[4] = rko[3] ^ rki[4];
		    rko[5] = rko[4] ^ rki[5];
		} else if key_len == 32 {
		    if i >= 6 {
			break;
		    }
		    rko[4] = subw(rko[3]) ^ rki[4];
		    rko[5] = rko[4] ^ rki[5];
		    rko[6] = rko[5] ^ rki[6];
		    rko[7] = rko[6] ^ rki[7];
		}

		i += 1;
		rc = mul_by_x(rc);
	    }
	}

	/*
	 * Generate the decryption keys for the Equivalent Inverse Cipher.
	 * This involves reversing the order of the round keys, and applying
	 * the Inverse Mix Columns transformation to all but the first and
	 * the last one.
	 */
	self.key_dec[0] = self.key_enc[key_len + 24];
	self.key_dec[1] = self.key_enc[key_len + 25];
	self.key_dec[2] = self.key_enc[key_len + 26];
	self.key_dec[3] = self.key_enc[key_len + 27];

	let mut i = 4;
	let mut j = key_len + 20;
	loop {
	    if j <= 0 {
		break;
	    }

	    self.key_dec[i]     = inv_mix_columns(self.key_enc[j]);
	    self.key_dec[i + 1] = inv_mix_columns(self.key_enc[j + 1]);
	    self.key_dec[i + 2] = inv_mix_columns(self.key_enc[j + 2]);
	    self.key_dec[i + 3] = inv_mix_columns(self.key_enc[j + 3]);

	    i += 4;
	    j -= 4;
	}

	self.key_dec[i]     = self.key_enc[0];
	self.key_dec[i + 1] = self.key_enc[1];
	self.key_dec[i + 2] = self.key_enc[2];
	self.key_dec[i + 3] = self.key_enc[3];

	Ok(())
    }

    pub fn set_key(&mut self, in_key: &[u8]) -> Result<(),()>
    {
	try!(self.expand_key(in_key));

	/*
	 * In order to force the compiler to emit data independent Sbox lookups
	 * at the start of each block, xor the first round key with values at
	 * fixed indexes in the Sbox. This will need to be repeated each time
	 * the key is used, which will pull the entire Sbox into the D-cache
	 * before any data dependent Sbox lookups are performed.
	 */
	self.key_enc[0] ^= (sbox_v( 0) ^ sbox_v(128)) as u32;
	self.key_enc[1] ^= (sbox_v(32) ^ sbox_v(160)) as u32;
	self.key_enc[2] ^= (sbox_v(64) ^ sbox_v(192)) as u32;
	self.key_enc[3] ^= (sbox_v(96) ^ sbox_v(224)) as u32;

	self.key_dec[0] ^= (inv_sbox_v( 0) ^ inv_sbox_v(128)) as u32;
	self.key_dec[1] ^= (inv_sbox_v(32) ^ inv_sbox_v(160)) as u32;
	self.key_dec[2] ^= (inv_sbox_v(64) ^ inv_sbox_v(192)) as u32;
	self.key_dec[3] ^= (inv_sbox_v(96) ^ inv_sbox_v(224)) as u32;

	Ok(())
    }

    pub fn encrypt(&self, out: &mut [u8], inp: &[u8])
    {
	debug_assert_eq!(out.len(), inp.len());
	// debug_assert_eq!(out.len(), BLOCK_SIZE)

	let mut rkp = &self.key_enc[4..];
	let rounds = 6 + self.key_length / 4;

	let mut st0 : [u32;4] = [
	    self.key_enc[0] ^ get_unaligned_le32(index_fixed!(&inp;..4)),
	    self.key_enc[1] ^ get_unaligned_le32(index_fixed!(&inp;4,..8)),
	    self.key_enc[2] ^ get_unaligned_le32(index_fixed!(&inp;8,..12)),
	    self.key_enc[3] ^ get_unaligned_le32(index_fixed!(&inp;12,..16)),
	];

	st0[0] ^= (sbox_v( 0) ^ sbox_v(128)) as u32;
	st0[1] ^= (sbox_v(32) ^ sbox_v(160)) as u32;
	st0[2] ^= (sbox_v(64) ^ sbox_v(192)) as u32;
	st0[3] ^= (sbox_v(96) ^ sbox_v(224)) as u32;

	let mut st1: [u32;4];
	let mut round = 0;
	loop {
	    st1 = [
		mix_columns(subshift(&st0, 0)) ^ rkp[0],
		mix_columns(subshift(&st0, 1)) ^ rkp[1],
		mix_columns(subshift(&st0, 2)) ^ rkp[2],
		mix_columns(subshift(&st0, 3)) ^ rkp[3],
	    ];

	    if round == rounds - 2 {
		break;
	    }

	    st0[0] = mix_columns(subshift(&st1, 0)) ^ rkp[4];
	    st0[1] = mix_columns(subshift(&st1, 1)) ^ rkp[5];
	    st0[2] = mix_columns(subshift(&st1, 2)) ^ rkp[6];
	    st0[3] = mix_columns(subshift(&st1, 3)) ^ rkp[7];

	    round += 2;
	    rkp = &{rkp}[8..];
	}

	put_unaligned_le32(subshift(&st1, 0) ^ rkp[4], index_fixed!(&mut out;..4));
	put_unaligned_le32(subshift(&st1, 1) ^ rkp[5], index_fixed!(&mut out;4,..8));
	put_unaligned_le32(subshift(&st1, 2) ^ rkp[6], index_fixed!(&mut out;8,..12));
	put_unaligned_le32(subshift(&st1, 3) ^ rkp[7], index_fixed!(&mut out;12,..16));
    }

    pub fn decrypt(&self, out: &mut [u8], inp: &[u8])
    {
	debug_assert_eq!(out.len(), inp.len());
	// debug_assert_eq!(out.len(), BLOCK_SIZE)

	let mut rkp = &self.key_dec[4..];
	let rounds: usize = 6 + self.key_length / 4;

	let mut st0 = [ 
	    self.key_dec[0] ^ get_unaligned_le32(index_fixed!(&inp;..4)),
	    self.key_dec[1] ^ get_unaligned_le32(index_fixed!(&inp;4,..8)),
	    self.key_dec[2] ^ get_unaligned_le32(index_fixed!(&inp;8,..12)),
	    self.key_dec[3] ^ get_unaligned_le32(index_fixed!(&inp;12,..16))
	];

	st0[0] ^= (inv_sbox_v( 0) ^ inv_sbox_v(128)) as u32;
	st0[1] ^= (inv_sbox_v(32) ^ inv_sbox_v(160)) as u32;
	st0[2] ^= (inv_sbox_v(64) ^ inv_sbox_v(192)) as u32;
	st0[3] ^= (inv_sbox_v(96) ^ inv_sbox_v(224)) as u32;

	let mut st1: [u32;4];

	let mut round = 0;
	loop {
	    st1 = [
		inv_mix_columns(inv_subshift(&st0, 0)) ^ rkp[0],
		inv_mix_columns(inv_subshift(&st0, 1)) ^ rkp[1],
		inv_mix_columns(inv_subshift(&st0, 2)) ^ rkp[2],
		inv_mix_columns(inv_subshift(&st0, 3)) ^ rkp[3],
	    ];

	    if round == rounds - 2 {
		break;
	    }

	    st0[0] = inv_mix_columns(inv_subshift(&st1, 0)) ^ rkp[4];
	    st0[1] = inv_mix_columns(inv_subshift(&st1, 1)) ^ rkp[5];
	    st0[2] = inv_mix_columns(inv_subshift(&st1, 2)) ^ rkp[6];
	    st0[3] = inv_mix_columns(inv_subshift(&st1, 3)) ^ rkp[7];

	    round += 2;
	    rkp = &{rkp}[8..];
	}

	put_unaligned_le32(inv_subshift(&st1, 0) ^ rkp[4], index_fixed!(&mut out;..4));
	put_unaligned_le32(inv_subshift(&st1, 1) ^ rkp[5], index_fixed!(&mut out;4,..8));
	put_unaligned_le32(inv_subshift(&st1, 2) ^ rkp[6], index_fixed!(&mut out;8,..12));
	put_unaligned_le32(inv_subshift(&st1, 3) ^ rkp[7], index_fixed!(&mut out;12,..16));
    }
}
