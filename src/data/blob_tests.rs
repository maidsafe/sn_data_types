// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::super::{utils, PublicKey, XorName};
use crate::data::{ChunkAddress, PrivateChunk, PublicChunk};
use bincode::deserialize as deserialise;
use hex::encode;
use rand::{self, Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::{env, iter, thread};
use threshold_crypto::SecretKey;
use unwrap::unwrap;

#[test]
fn deterministic_name() {
    let data1 = b"Hello".to_vec();
    let data2 = b"Goodbye".to_vec();

    let owner1 = PublicKey::Bls(SecretKey::random().public_key());
    let owner2 = PublicKey::Bls(SecretKey::random().public_key());

    let chunk1 = PrivateChunk::new(data1.clone(), owner1);
    let chunk2 = PrivateChunk::new(data1, owner2);
    let chunk3 = PrivateChunk::new(data2.clone(), owner1);
    let chunk3_clone = PrivateChunk::new(data2, owner1);

    assert_eq!(chunk3, chunk3_clone);

    assert_ne!(chunk1.name(), chunk2.name());
    assert_ne!(chunk1.name(), chunk3.name());
    assert_ne!(chunk2.name(), chunk3.name());
}

#[test]
fn deterministic_test() {
    let value = "immutable data value".to_owned().into_bytes();
    let chunk = PublicChunk::new(value);
    let chunk_name = encode(chunk.name().0.as_ref());
    let expected_name = "fac2869677ee06277633c37ac7e8e5c655f3d652f707c7a79fab930d584a3016";

    assert_eq!(&expected_name, &chunk_name);
}

#[test]
fn serialisation() {
    let mut rng = get_rng();
    let len = rng.gen_range(1, 10_000);
    let value = iter::repeat_with(|| rng.gen()).take(len).collect();
    let chunk = PublicChunk::new(value);
    let serialised = utils::serialise(&chunk);
    let parsed = unwrap!(deserialise(&serialised));
    assert_eq!(chunk, parsed);
}

fn get_rng() -> XorShiftRng {
    let env_var_name = "RANDOM_SEED";
    let seed = env::var(env_var_name)
        .ok()
        .map(|value| {
            unwrap!(
                value.parse::<u64>(),
                "Env var 'RANDOM_SEED={}' is not a valid u64.",
                value
            )
        })
        .unwrap_or_else(rand::random);
    println!(
        "To replay this '{}', set env var {}={}",
        unwrap!(thread::current().name()),
        env_var_name,
        seed
    );
    XorShiftRng::seed_from_u64(seed)
}

#[test]
fn zbase32_encode_decode_chunk_address() {
    let name = XorName(rand::random());
    let address = ChunkAddress::Public(name);
    let encoded = address.encode_to_zbase32();
    let decoded = unwrap!(ChunkAddress::decode_from_zbase32(&encoded));
    assert_eq!(address, decoded);
}
