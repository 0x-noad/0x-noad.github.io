// ES Module version of noble_bn254.js
import { Fp } from './abstract/modular.mjs';
import { weierstrass } from './abstract/weierstrass.mjs';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes } from '@noble/hashes/utils';

export const bn254 = weierstrass({
    a: 0n,
    b: 3n,
    Fp: Fp(21888242871839275222246405745257275088548364400416034343698204186575808495617n),
    n: 21888242871839275222246405745257275088548364400416034343698204186575808495617n,
    Gx: 1n,
    Gy: 2n,
    hash: sha256,
    hmac: (key, ...msgs) => hmac(sha256, key, concatBytes(...msgs)),
    randomBytes: randomBytes,
    h: 1n
});

