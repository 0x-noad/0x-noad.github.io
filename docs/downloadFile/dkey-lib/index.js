// Simplified JavaScript version of dkey-lib for downloadFile page
// Only includes what's needed: DkeyUserProfile.deserialize() and DKey.decryptFile()

// Import elgamal as ES module
import { Point, G, fp, getInRange, decrypt as elGamalDecrypt } from './EC-ElGamal/build/elgamal.mjs';

const constants = {
  curve: {
    Point: Point,
    G: G,
    fp: fp,
    getInRange: getInRange,
    createBN254KeyPair: () => {
      let [secret, pub] = elgamal.key_pair();
      const secretKey = secret.toString();
      const pubKeyX = pub.px.toString();
      const pubKeyY = pub.py.toString();
      return { secretKey, pubKeyX, pubKeyY };
    }
  }
};

// AES Decrypt utility
const aesDecryptToBytes = async (encryptedData, password) => {
  let arrayBuffer;
  if (encryptedData instanceof ArrayBuffer) {
    arrayBuffer = encryptedData;
  } else if (encryptedData instanceof Blob) {
    arrayBuffer = await encryptedData.arrayBuffer();
  } else if (encryptedData instanceof Uint8Array) {
    arrayBuffer = encryptedData.buffer;
  } else {
    throw new Error(`Invalid encryptedData type: ${encryptedData.constructor.name}. Expected ArrayBuffer, Blob, or Uint8Array.`);
  }
  
  const encryptedBytes = new Uint8Array(arrayBuffer);
  const salt = encryptedBytes.slice(8, 16);
  const ciphertext = encryptedBytes.slice(16);
  
  if (ciphertext.length % 16 !== 0) {
    throw new Error(`Ciphertext length (${ciphertext.length}) is not a multiple of 16 bytes`);
  }

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

// Validation functions
function isValidCID(cid) {
  try {
    // Simple CID validation - just check it's a string
    // For full validation, would need multiformats library
    return typeof cid === 'string' && cid.length > 0;
  } catch {
    return false;
  }
}

function isPointOnCurve(point) {
  try {
    new Point(BigInt(point[0]), BigInt(point[1]), BigInt(1));
    return true;
  } catch {
    return false;
  }
}

// Classes
class ListingMetadata {
  constructor(seller, fileName, fileDescription, fileSizeInBytes, suggestedPriceInEth, coverPhotoCID, coverPhotoLink, chainIds, listingCreatedAfterBlock) {
    this.seller = seller;
    this.fileName = fileName;
    this.fileDescription = fileDescription;
    this.fileSizeInBytes = fileSizeInBytes;
    this.suggestedPriceInEth = suggestedPriceInEth;
    this.coverPhotoCID = coverPhotoCID;
    this.coverPhotoLink = coverPhotoLink;
    this.chainIds = chainIds;
    this.listingCreatedAfterBlock = listingCreatedAfterBlock;
  }
}

class Listing {
  constructor(ipfsCID, metadata, fileSecretKey, howManyDKeysForSale, royaltyPercentage, totalSalesInEth) {
    if (!isValidCID(ipfsCID)) {
      throw new Error("Invalid IPFS CID");
    }
    if (!isPointOnCurve(fileSecretKey)) {
      throw new Error("Invalid file secret key");
    }
    
    this.ipfsCID = ipfsCID;
    this.metadata = metadata;
    this.fileSecretKey = fileSecretKey;
    this.howManyDKeysForSale = howManyDKeysForSale;
    this.howManyDKeysSold = 0;
    this.royaltyPercentage = royaltyPercentage;
    this.canDkeysBeSold = false;
    this.pksThatHaveReceivedDkeys = [];
    this.totalSalesInEth = totalSalesInEth;
  }

  dkeyProvidedTo(pubKeyX, bidAmountInEth) {
    this.pksThatHaveReceivedDkeys.push(pubKeyX);
    this.howManyDKeysSold++;
    this.canDkeysBeSold = this.howManyDKeysSold >= this.howManyDKeysForSale;
    this.totalSalesInEth += bidAmountInEth;
  }
}

class Bid {
  constructor(ipfsCID, bidAmountInEth, bidderAddress, pubKeyX, pubKeyY, secretKey, chainId, fileName, bidBlockNumber, canSell) {
    this.ipfsCID = ipfsCID;
    this.bidAmountInEth = bidAmountInEth;
    this.bidderAddress = bidderAddress;
    this.pubKeyX = pubKeyX;
    this.pubKeyY = pubKeyY;
    this.secretKey = secretKey;
    this.chainId = chainId;
    this.fileName = fileName;
    this.bidBlockNumber = bidBlockNumber;
    this.isFilled = false;
    this.canSell = canSell || false;
  }
}

class DKey {
  constructor(ipfsCID, ownerAddress, pubKeyX, pubKeyY, encryptedDKey, secretKey, fileName, chainId, amountPaidInEth) {
    this.ipfsCID = ipfsCID;
    this.ownerAddress = ownerAddress;
    this.pubKeyX = pubKeyX;
    this.pubKeyY = pubKeyY;
    this.encryptedDKey = encryptedDKey;
    this.secretKey = secretKey;
    this.fileName = fileName;
    this.chainId = chainId;
    this.canSell = false;
    this.amountPaidInEth = amountPaidInEth;
  }

  decryptFileSecretKey() {
    const eM = new Point(BigInt(this.encryptedDKey[0]), BigInt(this.encryptedDKey[1]), BigInt(1));
    const ke = new Point(BigInt(this.encryptedDKey[2]), BigInt(this.encryptedDKey[3]), BigInt(1));
    // Match TypeScript code order: elGamalDecrypt(secretKey, eM, ke)
    const cleartext = elGamalDecrypt(BigInt(this.secretKey), eM, ke);
    const affine = cleartext.toAffine();
    const fileSecretKeyX = affine.x.toString();
    const fileSecretKeyY = affine.y.toString();
    return [fileSecretKeyX, fileSecretKeyY];
  }

  async decryptFile(encryptedBuffer) {
    const fileSecretKey = this.decryptFileSecretKey();
    const password = `${fileSecretKey[0]}${fileSecretKey[1]}`;
    return await aesDecryptToBytes(encryptedBuffer, password);
  }
}

class DkeyUserProfile {
  constructor(userInfo, addresses, myListings, myDKeys, myOpenBids, config) {
    this.userInfo = userInfo;
    this.addresses = addresses;
    this.myListings = myListings || {};
    this.myDKeys = myDKeys || {};
    this.myOpenBids = myOpenBids || {};
    this.config = config;
  }

  static deserialize(jsonString, config) {
    const data = JSON.parse(jsonString);
  
    Object.keys(data.myListings || {}).forEach((chainId) => {
      if (!data.myListings[chainId]) return;
      Object.keys(data.myListings[chainId]).forEach((ipfsCID) => {
        const listingData = data.myListings[chainId][ipfsCID];
  
        const metadata = new ListingMetadata(
          listingData.metadata.seller,
          listingData.metadata.fileName,
          listingData.metadata.fileDescription,
          listingData.metadata.fileSizeInBytes,
          listingData.metadata.suggestedPriceInEth,
          listingData.metadata.coverPhotoCID,
          listingData.metadata.coverPhotoLink,
          listingData.metadata.chainIds,
          listingData.metadata.listingCreatedAfterBlock
        );
  
        const listing = new Listing(
          listingData.ipfsCID,
          metadata,
          listingData.fileSecretKey,
          listingData.howManyDKeysForSale,
          listingData.royaltyPercentage,
          listingData.totalSalesInEth
        );
        
        listing.howManyDKeysSold = listingData.howManyDKeysSold || 0;
        listing.canDkeysBeSold = listingData.canDkeysBeSold || false;
        listing.pksThatHaveReceivedDkeys = listingData.pksThatHaveReceivedDkeys || [];
  
        data.myListings[chainId][ipfsCID] = listing;
      });
    });
  
    Object.keys(data.myDKeys || {}).forEach((chainId) => {
      if (!data.myDKeys[chainId]) return;
      Object.keys(data.myDKeys[chainId]).forEach((ipfsCID) => {
        const dkeyData = data.myDKeys[chainId][ipfsCID];
  
        const dkey = new DKey(
          dkeyData.ipfsCID,
          dkeyData.ownerAddress,
          dkeyData.pubKeyX,
          dkeyData.pubKeyY,
          dkeyData.encryptedDKey,
          dkeyData.secretKey,
          dkeyData.fileName,
          dkeyData.chainId,
          dkeyData.amountPaidInEth
        );
  
        dkey.canSell = dkeyData.canSell || false;
        data.myDKeys[chainId][ipfsCID] = dkey;
      });
    });
  
    Object.keys(data.myOpenBids || {}).forEach((chainId) => {
      if (!data.myOpenBids[chainId]) return;
      Object.keys(data.myOpenBids[chainId]).forEach((ipfsCID) => {
        const bidData = data.myOpenBids[chainId][ipfsCID];
  
        const bid = new Bid(
          bidData.ipfsCID,
          bidData.bidAmountInEth,
          bidData.bidderAddress,
          bidData.pubKeyX,
          bidData.pubKeyY,
          bidData.secretKey,
          bidData.chainId,
          bidData.fileName,
          bidData.bidBlockNumber,
          bidData.canSell
        );
  
        bid.isFilled = bidData.isFilled || false;
        data.myOpenBids[chainId][ipfsCID] = bid;
      });
    });
  
    return new DkeyUserProfile(
      data.userInfo,
      data.addresses,
      data.myListings,
      data.myDKeys,
      data.myOpenBids,
      config
    );
  }
}

// Export as ES module
export { DkeyUserProfile, DKey, Listing, ListingMetadata, Bid, constants };

// Also expose on window for script tag usage
if (typeof window !== 'undefined') {
  window.DkeyUserProfile = DkeyUserProfile;
  window.DKey = DKey;
}

