import { Fp } from './abstract/modular.ts';
import { weierstrass } from './abstract/weierstrass.ts';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, randomBytes } from '@noble/hashes/utils';

 
export const bn254 = weierstrass({
    a: BigInt(0),
    b: BigInt(3),
    Fp: Fp(BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617")),
    n: BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617"),
    Gx: BigInt(1),
    Gy: BigInt(2),
    hash: sha256,
    hmac: (key: Uint8Array, ...msgs: Uint8Array[]) => hmac(sha256, key, concatBytes(...msgs)),
    randomBytes,
    h: BigInt(1)
});

