import BigNumber from 'bignumber.js';
declare let snarkjs: any;

export const makeProof = async (_proofInput: any, _wasm: any, _zkey: any) => {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(_proofInput, _wasm, _zkey);
  return { proof, publicSignals };
};

export const verifyProof = async (_verificationkey: any, signals: any, proof: any) => {
  const vkey = await fetch(_verificationkey).then(function (res) {
    return res.json();
  });

  const res = await snarkjs.groth16.verify(vkey, signals, proof);
  return res;
};

export function p256(n: any) {
  let nstr = new BigNumber(n).toString(16);
  while (nstr.length < 64) nstr = '0' + nstr;
  nstr = '0x' + nstr;
  return nstr;
}

export const groth16ExportSolidityCallData = async (proof: any, pub: any) => {
  let inputs = [];
  for (let i = 0; i < pub.length; i++) {
    inputs.push(p256(pub[i]));
  }

  let P;
  P = [[p256(proof.pi_a[0]), p256(proof.pi_a[1])],
  [[p256(proof.pi_b[0][1]), p256(proof.pi_b[0][0])], [p256(proof.pi_b[1][1]), p256(proof.pi_b[1][0])]],
  [p256(proof.pi_c[0]), p256(proof.pi_c[1])],
      inputs
  ];
  return P;
};

export const aesEncrypt = async (data: ArrayBuffer | string, password: string) => {
    const pbkdf2iterations = 10000;
    const passphraseBytes = new TextEncoder().encode(password);
    const pbkdf2Salt = window.crypto.getRandomValues(new Uint8Array(8));
  
    const passphraseKey = await window.crypto.subtle.importKey('raw', passphraseBytes, { name: 'PBKDF2' }, false, ['deriveBits']);
    const pbkdf2Bytes = await window.crypto.subtle.deriveBits({ name: 'PBKDF2', salt: pbkdf2Salt, iterations: pbkdf2iterations, hash: 'SHA-256' }, passphraseKey, 384);
    const pbkdf2BytesArray = new Uint8Array(pbkdf2Bytes);
  
    const keyBytes = pbkdf2BytesArray.slice(0, 32);
    const ivBytes = pbkdf2BytesArray.slice(32);
  
    const key = await window.crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC', length: 256 }, false, ['encrypt']);
    const plaintextBytes = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
  
    const cipherBytes = await window.crypto.subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, key, plaintextBytes);
    const cipherBytesArray = new Uint8Array(cipherBytes);
  
    const resultBytes = new Uint8Array(cipherBytesArray.length + 16);
    resultBytes.set(new TextEncoder().encode('Salted__'));
    resultBytes.set(pbkdf2Salt, 8);
    resultBytes.set(cipherBytesArray, 16);
  
    return new Blob([resultBytes], { type: 'application/download' });
};

export const aesDecrypt = async (encryptedData: ArrayBuffer, password: string) => {
    console.log("starting aes decrypt")
    const encryptedBytes = new Uint8Array(encryptedData);
    const salt = encryptedBytes.slice(8, 16);
    const ciphertext = encryptedBytes.slice(16);
  
    const pbkdf2iterations = 10000;
    const passphraseBytes = new TextEncoder().encode(password);
    
    const passphraseKey = await window.crypto.subtle.importKey(
      'raw',
      passphraseBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const pbkdf2Bytes = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: pbkdf2iterations,
        hash: 'SHA-256'
      },
      passphraseKey,
      384
    );
  
    const pbkdf2BytesArray = new Uint8Array(pbkdf2Bytes);
    const keyBytes = pbkdf2BytesArray.slice(0, 32);
    const ivBytes = pbkdf2BytesArray.slice(32);
  
    const key = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'AES-CBC', length: 256 },
      false,
      ['decrypt']
    );
    
    const decryptedBytes = await window.crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: ivBytes },
      key,
      ciphertext
    );
  
    return new TextDecoder().decode(decryptedBytes);
}

export const aesDecryptToBytes = async (encryptedData: ArrayBuffer, password: string): Promise<Uint8Array> => {
  const encryptedBytes = new Uint8Array(encryptedData);
  const salt = encryptedBytes.slice(8, 16);
  const ciphertext = encryptedBytes.slice(16);

  const pbkdf2iterations = 10000;
  const passphraseBytes = new TextEncoder().encode(password);

  const passphraseKey = await window.crypto.subtle.importKey(
    'raw',
    passphraseBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const pbkdf2Bytes = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: pbkdf2iterations,
      hash: 'SHA-256'
    },
    passphraseKey,
    384
  );

  const pbkdf2BytesArray = new Uint8Array(pbkdf2Bytes);
  const keyBytes = pbkdf2BytesArray.slice(0, 32);
  const ivBytes = pbkdf2BytesArray.slice(32);

  const key = await window.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-CBC', length: 256 },
    false,
    ['decrypt']
  );

  const decryptedBytes = await window.crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: ivBytes },
    key,
    ciphertext
  );

  return new Uint8Array(decryptedBytes);
};