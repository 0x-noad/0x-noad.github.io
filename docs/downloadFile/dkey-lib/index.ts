import { CID } from 'multiformats';
import { base32 } from 'multiformats/bases/base32';
import { ethers } from 'ethers';
import { key_pair, decrypt as elGamalDecrypt } from "./EC-ElGamal/build/elgamal.ts";
import { BigNumber } from 'bignumber.js';
import { contracts } from "./contracts";
import { keccak256, TransactionReceipt, type Address } from "viem";
import { readContract, writeContract, type WriteContractReturnType, waitForTransactionReceipt, getPublicClient } from '@wagmi/core';
import { groth16ExportSolidityCallData, verifyProof, makeProof, aesEncrypt, aesDecrypt, aesDecryptToBytes } from './utils';
import { constants } from './constants';


// interfaces ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * A standard result object returned from DkeyUserProfile-related transactions.
 * Used across DkeyUserProfile methods to encapsulate success/failure and returned data.
 */
interface TransactionResult {
  success: boolean;
  profile?: DkeyUserProfile; 
  receipt?: TransactionReceipt; 
  result?: any;
}

/**
 * All the possible `result` values returned in a TransactionResult.
 */
const RESULTS = {
  // `success: true`
  NO_UPDATES_TO_PROFILE: "NO_UPDATES_TO_PROFILE",
  PROFILE_UPDATED: "PROFILE_UPDATED",
  BLOCKCHAIN_INTERACTION_SUCCESSFUL: "BLOCKCHAIN_INTERACTION_SUCCESSFUL",

  // `success: false`
  BLOCKCHAIN_INTERACTION_FAILED: "BLOCKCHAIN_INTERACTION_FAILED",
  LOCAL_ZK_PROOF_VERIFICATION_FAILED: "LOCAL_ZK_PROOF_VERIFICATION_FAILED",
  ZK_PROOF_GENERATION_ERROR: "ZK_PROOF_GENERATION_ERROR",
  UNSUPPORTED_CHAIN_ID: "UNSUPPORTED_CHAIN_ID",
  WRONG_ADDRESS_CONNECTED: "WRONG_ADDRESS_CONNECTED",
  LISTING_NOT_FOUND: "LISTING_NOT_FOUND",
  DKEY_NOT_FOUND: "DKEY_NOT_FOUND",
  BID_NOT_FOUND: "BID_NOT_FOUND",
  BID_ALREADY_EXISTS_FOR_THIS_LISTING: "BID_ALREADY_EXISTS_FOR_THIS_LISTING",
  INVALID_BID_AMOUNT: "INVALID_BID_AMOUNT",
  INVALID_BATCH_SIZE: "INVALID_BATCH_SIZE",
  INVALID_PK_IN_BATCH: "INVALID_PK_IN_BATCH",
  INVALID_CID: "INVALID_CID",
};

// validations ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Checks whether a given string is a valid IPFS CID.
 * @param cid - The CID string to validate.
 * @returns True if the CID is valid, otherwise false.
 */
function isValidCID(cid: string): boolean {
  try {
    CID.parse(cid);
    return true;
  } catch {
    return false;
  }
}

/**
 * Verifies whether the given coordinates form a valid point on the BN254 elliptic curve.
 * @param point - A tuple containing the x and y coordinates as strings.
 * @returns True if the point lies on the curve, otherwise false.
 */
function isPointOnCurve(point: [string, string]): boolean {
  try {
    new constants.curve.Point(BigInt(point[0]), BigInt(point[1]), BigInt(1));
    return true;
  } catch {
    return false;
  }
}

// classes ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Represents metadata associated with a listing. Gets pinned to IPFS in a directory with the encrypted file (eg: examplegateway.com/ipfs/{ipfsCID}/metadata.json).
 * Contains seller info, file details, and supported chains.
 */
class ListingMetadata { 
  readonly seller: object;                        // FYI: should contain fields like fid, fname, twitterUrl, etc... will be specific to different front ends
  readonly fileName: string;                      // FYI: needs to include the file extension, or buyer can't reconstruct the decrypted file
  readonly fileDescription: string;
  readonly fileSizeInBytes: number;
  readonly suggestedPriceInEth: number;
  readonly coverPhotoCID: string;
  readonly coverPhotoLink: string;
  readonly chainIds: number[];                    // FYI: making this an array for forward compatibility (need to implement deploying the same Listing on multiple chains)
  readonly listingCreatedAfterBlock: number;      // FYI: used to narrow the number of blocks to query when fetching bids

  constructor(seller: object, fileName: string, fileDescription: string, fileSizeInBytes: number, suggestedPriceInEth: number, coverPhotoCID: string, coverPhotoLink: string, chainIds: number[], listingCreatedAfterBlock: number) {
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

/**
 * Manages the data and functions required to maintain a user's Listing.
 * Stores the CID, file secret key, metadata, and sales info.
 */
class Listing {
  readonly ipfsCID: string;
  readonly metadata: ListingMetadata;           // FYI: immutable because it's already uploaded to IPFS at this point
  readonly fileSecretKey: [string, string];
  readonly howManyDKeysForSale: number;         // AKA: the max number of keys that the seller can sell before (i) they can no longer sell any more, (ii) the buyers can sell theirs, and (iii) royalties on trades are applied
  readonly royaltyPercentage: number;           // AKA: the percentage of the sale that the seller gets on subsequent trades of Dkeys
  howManyDKeysSold: number;
  canDkeysBeSold: boolean;                      // AKA: true if howManyDKeysSold >= howManyDKeysForSale
  pksThatHaveReceivedDkeys: string[];           // AKA: array of pubKeyXs that this user sent Dkeys to
  totalSalesInEth: number;

  constructor(
    ipfsCID: string,
    metadata: ListingMetadata,
    fileSecretKey: [string, string],
    howManyDKeysForSale: number,
    royaltyPercentage: number,
    totalSalesInEth: number,
  ) {
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

  dkeyProvidedTo(pubKeyX: string, bidAmountInEth: number) {
    this.pksThatHaveReceivedDkeys.push(pubKeyX);
    this.howManyDKeysSold++;
    this.canDkeysBeSold = this.howManyDKeysSold >= this.howManyDKeysForSale;
    this.totalSalesInEth += bidAmountInEth;
  }

  batchDkeysProvidedTo(pubKeyXs: string[], bidAmountsInEth: number[]) {
    this.pksThatHaveReceivedDkeys.push(...pubKeyXs);
    this.howManyDKeysSold += pubKeyXs.length;
    this.canDkeysBeSold = this.howManyDKeysSold >= this.howManyDKeysForSale;
    this.totalSalesInEth += bidAmountsInEth.reduce((acc, curr) => acc + curr, 0);
  }
}

/**
 * Manages the data and functions associated with a user's open bid.
 */
class Bid {
  readonly ipfsCID: string;
  bidAmountInEth: number;
  readonly bidderAddress: Address;
  readonly pubKeyX: string;
  readonly pubKeyY: string;
  readonly secretKey: string;
  readonly chainId: number;
  readonly fileName: string;
  readonly bidBlockNumber: number;
  isFilled: boolean;
  canSell: boolean;

  constructor(ipfsCID: string, bidAmountInEth: number, bidderAddress: Address, pubKeyX: string, pubKeyY: string, secretKey: string, chainId: number, fileName: string, bidBlockNumber: number, canSell?: boolean) {
    this.ipfsCID = ipfsCID;
    this.bidAmountInEth = bidAmountInEth;
    this.bidderAddress = bidderAddress;
    this.pubKeyX = pubKeyX;
    this.pubKeyY = pubKeyY;
    this.secretKey = secretKey;
    this.chainId = chainId;
    this.fileName = fileName;
    this.isFilled = false;                      // FYI: true if DkeyProvided event has been fired for this bid (then once Dkey is grabbed from subgraph/blockchain and .dkeyReceived() is called, Bid gets deleted and new Dkey is created)
    this.canSell = canSell || false;            // FYI: true if DkeysCanBeSold event has been fired for this ipfsCid
    this.bidBlockNumber = bidBlockNumber;
  }

  increaseBidAmount(increaseBidAmountInEth: number) {
    this.bidAmountInEth += increaseBidAmountInEth;
  }
}

class BidLite {
  readonly bidNumber: number;
  readonly ipfsCID: string;
  bidAmountInEth: string;
  readonly pubKeyX: string;
  readonly pubKeyY: string;
  isOpen: boolean;

  constructor(bidNumber: number, ipfsCID: string, pubKeyX: string, pubKeyY: string, bidAmountInEth?: string) {
    this.bidNumber = bidNumber;
    this.ipfsCID = ipfsCID;
    this.pubKeyX = pubKeyX;
    this.pubKeyY = pubKeyY;
    this.bidAmountInEth = bidAmountInEth || "0";
    this.isOpen = true;
  }
}

/**
 * Manages the data and functions associated with a user's DKey.
 * A DKey class object is created after the user's bid is successfully filled.
 */
class DKey {
  readonly ipfsCID: string;
  readonly ownerAddress: Address;
  readonly pubKeyX: string;                     // FYI: used as a reference key in the smart contract's xToBid mapping 
  readonly pubKeyY: string;                     // FYI: used as a reference key in the smart contract's xToBid mapping 
  readonly encryptedDKey: [string, string, string, string];  // [eM.x, eM.y, ke.x, ke.y] - encrypted fileSecretKey
  readonly secretKey: string;                  // Secret key needed to decrypt encryptedDKey
  readonly chainId: number;
  readonly fileName: string;
  canSell: boolean;
  amountPaidInEth: number;

  constructor(ipfsCID: string, ownerAddress: Address, pubKeyX: string, pubKeyY: string, encryptedDKey: [string, string, string, string], secretKey: string, fileName: string, chainId: number, amountPaidInEth: number) {
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

  // Helper method to decrypt the encryptedDKey to get fileSecretKey
  decryptFileSecretKey(): [string, string] {
    const eM = new constants.curve.Point(BigInt(this.encryptedDKey[0]), BigInt(this.encryptedDKey[1]), BigInt(1));
    const ke = new constants.curve.Point(BigInt(this.encryptedDKey[2]), BigInt(this.encryptedDKey[3]), BigInt(1));
    const cleartext = elGamalDecrypt(BigInt(this.secretKey), eM, ke);
    const fileSecretKeyX = cleartext.toAffine().x.toString();
    const fileSecretKeyY = cleartext.toAffine().y.toString();
    return [fileSecretKeyX, fileSecretKeyY];
  }

  // dont really need this, can use DkeyUserProfile.checkIfDKeysCanBeSold() instead
  async checkCanSellDkey(config: any): Promise<TransactionResult> {
    const ipfsCIDBytesString = dkey.formatCID(this.ipfsCID).ipfsCIDBytesString;

    try {
      const result = await readContract(config, {
        address: contracts.DKeyStoreL2[this.chainId as keyof typeof contracts.DKeyStoreL2].address,
        abi: contracts.DKeyStoreL2[this.chainId as keyof typeof contracts.DKeyStoreL2]?.abi,
        functionName: "checkIfDkeysCanBeSold",
        args: [ipfsCIDBytesString],
      }) as boolean;

      console.log("canSellDkey result:", result);

      this.canSell = result;
      return { success: true, result: RESULTS.BLOCKCHAIN_INTERACTION_SUCCESSFUL };
    } catch (error) {
      console.error("Error checking if Dkey can be sold:", error);
      return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
    }
  }

  async decryptFile(encryptedBuffer: ArrayBuffer): Promise<Uint8Array> {
    const fileSecretKey = this.decryptFileSecretKey();
    return await aesDecryptToBytes(
      encryptedBuffer,
      `${fileSecretKey[0]}${fileSecretKey[1]}`
    );
  }
}

/**
 * Manages a user's profile, including their Listings, Bids, and acquired DKeys.
 * Provides methods to complete all the protocol's blockchain interactions.
 * Encrypts/decrypts and serializes/deserializes a user's data for storage/retrieval between sessions.
 */
class DkeyUserProfile {
  private config: any;                                              // not saving the config to the object, as configs will change accross different front-ends

  // Listings, DKeys, and Bids are all grouped by chainId
  userInfo: Record<string, any>;
  addresses: Record<number, Address>;                               // one address per chain (all writeContract txs for a given chainId need to match addresses[chainId])
  myListings: Record<number, Record<string, Listing>>;
  myDKeys: Record<number, Record<string, DKey>>;
  myOpenBids: Record<number, Record<string, Bid>>;

  constructor(
    userInfo: Record<string, any>,
    addresses: Record<number, Address>,
    myListings: Record<number, Record<string, Listing>>,
    myDKeys: Record<number, Record<string, DKey>>,
    myOpenBids: Record<number, Record<string, Bid>>,
    config: any,                                                    // frontend passes in their own wagmi config with their own connectors/RPC URLs
  ) {
    this.userInfo = userInfo;
    this.addresses = addresses;
    this.myListings = myListings || {};
    this.myDKeys = myDKeys || {};
    this.myOpenBids = myOpenBids || {};
    this.config = config;
  }

  /**
   * Creates a new file listing on the blockchain using the provided metadata and file secret key.
   * Adds the new listing to the user's profile if the transaction is successful.
   * 
   * TODO: add support for creating listing on multiple chains (or at least being able to create on one chain, and easily duplicate on other chains)
   *
   * @param ipfsCID - The IPFS Content Identifier of the encrypted file.
   * @param metadata - Metadata associated with the listing, including seller, filename, description, and supported chains.
   * @param fileSecretKey - The BN254 elliptic curve secret key used to encrypt the file, as a [x, y] pair.
   * @param howManyDKeysForSale - Total number of decryption keys the seller intends to distribute before secondary sales become possible.
   * @param royaltyPercentage - Percentage of resale value the original seller will receive on secondary sales.
   * @param address - The user's wallet address (must match the connected address on the selected chain).
   * @returns A promise resolving to a TransactionResult indicating success or failure, including the updated profile or error message.
   */
  async createListing(
    ipfsCID: string, 
    metadata: ListingMetadata, 
    fileSecretKey: [string, string], 
    howManyDKeysForSale: number, 
    royaltyPercentage: number,
    address: Address,
  ): Promise<TransactionResult> {
    const chainId = metadata.chainIds[0];
    if (!contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2]) {
      return { success: false, result: RESULTS.UNSUPPORTED_CHAIN_ID };
    }

    // if there's an address already saved for this chain, make sure user is connected to that address
    if (this.addresses[chainId as keyof typeof this.addresses] && this.addresses[chainId as keyof typeof this.addresses] !== address) {
      return { success: false, result: RESULTS.WRONG_ADDRESS_CONNECTED };
    }
    
    let ipfsCIDBytesString: string;
    try {
      ipfsCIDBytesString = dkey.formatCID(ipfsCID).ipfsCIDBytesString;
    } catch (error) {
      return { success: false, result: RESULTS.INVALID_CID };
    }

    ////////////////////////////////////////////////////////////////
    // for performance, need to swap all this out with a poseidon hash function (although it does also work as a check that fileSecretKey is valid)
    // (where the output of poseidonHash([fileSecretKey[0], fileSecretKey[1]]) matches `calldata[3][4]`)
    let [secret, pub] = key_pair();
    const input = {
        "M": [fileSecretKey[0], fileSecretKey[1]],
        "k": constants.curve.getInRange(BigInt(1), constants.curve.fp).toString(),
        "pk": [pub.px.toString(), pub.py.toString()]
    };
    const proofAndSignals = await makeProof(input, constants.circuit.wasmFile, constants.circuit.zkeyFile);
    const calldata = await groth16ExportSolidityCallData(proofAndSignals.proof, proofAndSignals.publicSignals);
    const poseidonHash = calldata[3][4]; // <-- all for this
    ////////////////////////////////////////////////////////////////

    try {
        const txResponse: WriteContractReturnType = await writeContract(this.config, {
            address: contracts.DKeyStoreL2[metadata.chainIds[0] as keyof typeof contracts.DKeyStoreL2].address,
            abi: contracts.DKeyStoreL2[metadata.chainIds[0] as keyof typeof contracts.DKeyStoreL2]?.abi,
            functionName: "createListing",
            args: [ipfsCIDBytesString, howManyDKeysForSale, royaltyPercentage, poseidonHash],
            account: this.addresses[metadata.chainIds[0] as keyof typeof this.addresses] || null, // if no address saved for this chain, use the current address
        });

        const txReceipt = await waitForTransactionReceipt(this.config, { hash: txResponse });

        if (txReceipt.status === 'success') {
            console.log("txReceipt", txReceipt);
            const newListing = new Listing(ipfsCID, metadata, fileSecretKey, howManyDKeysForSale, royaltyPercentage, 0);
            
            if (!this.myListings[metadata.chainIds[0]]) {
              this.myListings[metadata.chainIds[0]] = {};
            }

            // if there's no address saved for this chain, save the address from the tx receipt
            if (!this.addresses[metadata.chainIds[0] as keyof typeof this.addresses]) {
              this.addresses[metadata.chainIds[0] as keyof typeof this.addresses] = txReceipt.from;
            }
            
            this.myListings[metadata.chainIds[0]][ipfsCID] = newListing;
            
            return { success: true, profile: this, receipt: txReceipt, result: RESULTS.BLOCKCHAIN_INTERACTION_SUCCESSFUL }; 
        } else {
            return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
        }
    } catch (error: any) {
        console.error("Blockchain transaction failed:", error);
        return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
    }
  }

  /**
   * Submits a bid to a listing on the blockchain.
   * Generates a new BN254 key pair and sends the public key along with the bid amount.
   * On success, stores the bid in the user's open bids for the corresponding chain.
   *
   * @param ipfsCID - The IPFS CID of the listing.
   * @param bidAmountInEth - The bid amount in ETH.
   * @param metadata - The Listing's metadata file (taken from IPFS).
   * @param address - The user's blockchain address (must match or initialize the saved address for the chain).
   * @param chainId - The blockchain chain ID where the listing resides.
   * @param canSell - Optional flag indicating whether DKeys can be resold immediately upon acquisition.
   * @returns A promise resolving to a TransactionResult indicating success or failure.
   */
  async makeBid(
    ipfsCID: string,
    bidAmountInEth: number,
    metadata: ListingMetadata,
    address: Address,
    chainId: number,
    canSell?: boolean,  // pass in canDkeysBeSold bool from dkey.fetchListingDetails()
  ): Promise<TransactionResult> {
    if (!contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2]) {
      console.log("unsupported chain id");
      return { success: false, result: RESULTS.UNSUPPORTED_CHAIN_ID };
    }

    if (this.addresses[chainId as keyof typeof this.addresses] && this.addresses[chainId as keyof typeof this.addresses] !== address) {
      console.log("wrong address connected");
      return { success: false, result: RESULTS.WRONG_ADDRESS_CONNECTED };
    }

    // this is opinionated:  smart contract allows for more than 1 bid per address, but generally makes more sense for a user to only have 1 bid per listing
    if (this.myOpenBids[chainId]?.[ipfsCID]) {
      console.log("bid already exists for this listing");
      return { success: false, result: RESULTS.BID_ALREADY_EXISTS_FOR_THIS_LISTING };
    }

    const { secretKey, pubKeyX, pubKeyY } = constants.curve.createBN254KeyPair();
    let ipfsCIDBytesString: string;
    try {
      ipfsCIDBytesString = dkey.formatCID(ipfsCID).ipfsCIDBytesString;
    } catch (error) {
      console.log("invalid cid");
      return { success: false, result: RESULTS.INVALID_CID };
    }
    const bigNumberWei = ethers.parseEther(bidAmountInEth.toString());
    const bigIntWei = BigInt(bigNumberWei.toString());
    const { address: contractAddress, abi } = contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2];

    try {
      const txResponse: WriteContractReturnType = await writeContract(this.config, {
        address: contractAddress,
        abi,
        functionName: "makeBid",
        args: [
          ipfsCIDBytesString,
          [pubKeyX, pubKeyY],
        ],
        value: bigIntWei,
        account: this.addresses[chainId as keyof typeof this.addresses] || null, // if no address saved for this chain, use the current address
      });

      const txReceipt = await waitForTransactionReceipt(this.config, { hash: txResponse });

      if (txReceipt.status === 'success') {
        const bidBlockNumber = Number(txReceipt.blockNumber); 
        const bid = new Bid(ipfsCID, bidAmountInEth, txReceipt.from, pubKeyX, pubKeyY, secretKey, chainId, metadata.fileName, bidBlockNumber, canSell);
        if (!this.myOpenBids[chainId]) {
          this.myOpenBids[chainId] = {};
        }

        if (!this.addresses[chainId as keyof typeof this.addresses]) {
          this.addresses[chainId as keyof typeof this.addresses] = txReceipt.from;
        }

        this.myOpenBids[chainId][ipfsCID] = bid;
        return { success: true, profile: this, receipt: txReceipt, result: RESULTS.BLOCKCHAIN_INTERACTION_SUCCESSFUL };
      } else {
        return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
      }
    } catch (error: any) {
      console.error("Blockchain transaction failed:", error);
      return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
    }
  }

  /**
   * The Listing owner fills a bid by encrypting the fileSecretKey for the bidder's public key.
   * The ciphertext (DKey) + proof are sent to the smart contract.
   * Upon success, updates the user's profile to show that the bidder has been provided a DKey.
   *
   * @param ipfsCID - The IPFS Content Identifier of the listing.
   * @param bidderPubKeyX - The X coordinate of the bidder's public decryption key.
   * @param bidderPubKeyY - The Y coordinate of the bidder's public decryption key.
   * @param bidAmountInEth - The amount of ETH that the bidder is paying for the DKey.
   * @param chainId - The blockchain chain ID where the listing resides.
   * @returns A promise resolving to a TransactionResult indicating success or failure, including the updated profile or an error.
   */
  async fillBid(
    ipfsCID: string,
    bidderPubKeyX: string,
    bidderPubKeyY: string,
    bidAmountInEth: number,
    chainId: number,
  ): Promise<TransactionResult> {
    if (!this.myListings[chainId][ipfsCID]) {
      return { success: false, result: RESULTS.LISTING_NOT_FOUND };
    }

    const [secret_key_x, secret_key_y] = this.myListings[chainId][ipfsCID].fileSecretKey;
    
    const input = {
      "M": [secret_key_x, secret_key_y],
      "k": constants.curve.getInRange(BigInt(1), constants.curve.fp).toString(),
      "pk": [bidderPubKeyX, bidderPubKeyY]
    };
    const proofAndSignals = await makeProof(input, constants.circuit.wasmFile, constants.circuit.zkeyFile);
    const verificationResult = await verifyProof(
      constants.circuit.verificationKey, 
      proofAndSignals.publicSignals, 
      proofAndSignals.proof
    );
    if (!verificationResult) {
      return { success: false, result: RESULTS.LOCAL_ZK_PROOF_VERIFICATION_FAILED };
    }
    const calldata = await groth16ExportSolidityCallData(
      proofAndSignals.proof, 
      proofAndSignals.publicSignals
    );

    const ipfsCIDBytesString = dkey.formatCID(ipfsCID).ipfsCIDBytesString;
    const { address: contractAddress, abi } = contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2];

    try {
      const txResponse: WriteContractReturnType = await writeContract(this.config, {
        address: contractAddress,
        abi,
        functionName: "fillBid",
        args: [ipfsCIDBytesString, calldata[0], calldata[1], calldata[2], calldata[3]],
        account: this.addresses[chainId as keyof typeof this.addresses]
      });

      const txReceipt = await waitForTransactionReceipt(this.config, { hash: txResponse });

      if (txReceipt.status === 'success') {
        console.log("successful tx");
        this.myListings[chainId][ipfsCID].dkeyProvidedTo(bidderPubKeyX, bidAmountInEth);
        return { success: true, profile: this, receipt: txReceipt, result: RESULTS.BLOCKCHAIN_INTERACTION_SUCCESSFUL };
      } else {
        return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
      }
    } catch (error: any) {
      console.error("Blockchain transaction failed:", error);
      return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
    }
  }

  /////////////////////////////////////////////////////////////////////////////////////
  // // zkey file is too big for github (600mb), so leaving out the batch circuits etc
  // // 
  /////////////////////////////////////////////////////////////////////////////////////
  // /**
  //  * The Listing owner fills multiple bids in a single transaction by generating a batch of ciphertexts (and a validity proof).
  //  * Accepts up to 50 bidder public keys. If fewer than 50 are provided, dummy keys are added to meet circuit constraints.
  //  * Upon success, updates the user's profile to show that the bidders have been provided DKeys.
  //  * To accurately track the total sales in ETH for the listing, the bidAmountsInEth array must be provided by the front-end.
  //  *
  //  * @param ipfsCID - The IPFS Content Identifier of the listing.
  //  * @param bidderPubKeys - An array of 2-element arrays, each representing a bidder's [X, Y] public key pair.
  //  * @param bidAmountsInEth - An array of the amount of each bid in ETH.
  //  * @param chainId - The blockchain chain ID where the listing resides.
  //  * @returns A promise resolving to a TransactionResult indicating success or failure, including the updated profile or error message.
  //  */
  // async batchFillBids(
  //   ipfsCID: string,
  //   bidderPubKeys: [string, string][],
  //   bidAmountsInEth: number[],
  //   chainId: number,
  // ): Promise<TransactionResult> {
  //   if (!this.myListings[chainId][ipfsCID]) {
  //     return { success: false, result: RESULTS.LISTING_NOT_FOUND };
  //   }

  //   if (bidderPubKeys.length < 2 || bidderPubKeys.length > 50) {
  //     return { success: false, result: RESULTS.INVALID_BATCH_SIZE };
  //   }

  //   if (bidderPubKeys.length !== bidAmountsInEth.length) {
  //     return { success: false, result: RESULTS.INVALID_BATCH_SIZE };
  //   }

  //   const [secret_key_x, secret_key_y] = this.myListings[chainId][ipfsCID].fileSecretKey;

  //   let pks = bidderPubKeys.flat()

  //   if (bidderPubKeys.length < 50) {
  //     // create "dummy" pubkey pairs (need 50 "pks" to satisfy circuit)
  //     for (let i=0; i < 50 - bidderPubKeys.length; i++) {
  //       const { secretKey, pubKeyX, pubKeyY } = constants.curve.createBN254KeyPair();
  //       pks.push(pubKeyX, pubKeyY)
  //     }
  //   }

  //   let ks = []
  //   for (let i = 0; i < 50; i++) {
  //     if (!isPointOnCurve([pks[2 * i], pks[2 * i + 1]])) {
  //       return { success: false, result: RESULTS.INVALID_PK_IN_BATCH };
  //     }

  //     ks.push(constants.curve.getInRange(BigInt(1), constants.curve.fp).toString());
  //   }
    
  //   const input = {
  //     "M": [secret_key_x, secret_key_y],
  //     "ks": ks,
  //     "pks": pks
  //   };
  //   const proofAndSignals = await makeProof(input, constants.batchCircuit.wasmFile, constants.batchCircuit.zkeyFile);
  //   const verificationResult = await verifyProof(
  //     constants.batchCircuit.verificationKey, 
  //     proofAndSignals.publicSignals, 
  //     proofAndSignals.proof
  //   );
  //   if (!verificationResult) {
  //     throw new Error("Failed to locally verify zero-knowledge proof");
  //   }
  //   const calldata = await groth16ExportSolidityCallData(
  //     proofAndSignals.proof, 
  //     proofAndSignals.publicSignals
  //   );

  //   const ipfsCIDBytesString = dkey.formatCID(ipfsCID).ipfsCIDBytesString;
  //   const { address: contractAddress, abi } = contracts[chainId as keyof typeof contracts];

  //   try {
  //     const txResponse: WriteContractReturnType = await writeContract(this.config, {
  //       address: contractAddress,
  //       abi,
  //       functionName: "batchFillBid",
  //       args: [ipfsCIDBytesString, calldata[0], calldata[1], calldata[2], calldata[3], bidderPubKeys.length],
  //       account: this.addresses[chainId as keyof typeof this.addresses]
  //     });

  //     const txReceipt = await waitForTransactionReceipt(this.config, { hash: txResponse });

  //     if (txReceipt.status === 'success') {
  //       console.log("successful tx");
  //       this.myListings[chainId][ipfsCID].batchDkeysProvidedTo(bidderPubKeys.map(pk => pk[0]), bidAmountsInEth);        
  //       return { success: true, profile: this, receipt: txReceipt, result: RESULTS.TRANSACTION_SUCCESSFUL };
  //     } else {
  //       return { success: false, result: RESULTS.TRANSACTION_FAILED };
  //     }
  //   } catch (error: any) {
  //     return { success: false, result: RESULTS.TRANSACTION_FAILED };
  //   }
  // }
  /////////////////////////////////////////////////////////////////////////////////////
  /////////////////////////////////////////////////////////////////////////////////////


  /**
   * Allows a DKey owner to re-sell their DKey by filling a bid.
   * They do so by encrypting the fileSecretKey for the bidder's public key, and generating a validity proof.
   * The ciphertext (DKey) + proof are sent to the smart contract.
   * Upon success, the DKey is deleted from the user's profile.
   *
   * @param ipfsCID - The IPFS Content Identifier associated with the DKey.
   * @param bidderPubKeyX - The X coordinate of the buyer's public decryption key.
   * @param bidderPubKeyY - The Y coordinate of the buyer's public decryption key.
   * @param chainId - The blockchain chain ID where the DKey resides.
   * @returns A promise resolving to a TransactionResult indicating success or failure, including the updated profile or error.
   */
  async sellDkey(
    ipfsCID: string,
    bidderPubKeyX: string,
    bidderPubKeyY: string,
    chainId: number,
  ): Promise<TransactionResult> {
    if (!this.myDKeys[chainId][ipfsCID]) {
      return { success: false, result: RESULTS.DKEY_NOT_FOUND };
    }

    try {
      const { address, abi } = contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2];
      const fileSecretKey = this.myDKeys[chainId][ipfsCID].decryptFileSecretKey();

      const input = {
        "M": [fileSecretKey[0], fileSecretKey[1]],
        "k": constants.curve.getInRange(BigInt(1), constants.curve.fp).toString(),
        "pk": [bidderPubKeyX, bidderPubKeyY]
      };
      let proofAndSignals;
      try {
        proofAndSignals = await makeProof(input, constants.circuit.wasmFile, constants.circuit.zkeyFile);
      } catch (error) {
        console.error("Error generating proof:", error);
        return { success: false, result: RESULTS.ZK_PROOF_GENERATION_ERROR };
      }
      const verificationResult = await verifyProof(
        constants.circuit.verificationKey, 
        proofAndSignals.publicSignals, 
        proofAndSignals.proof
      );
      if (!verificationResult) {
        console.error("Error verifying zero-knowledge proof:", verificationResult);
        return { success: false, result: RESULTS.LOCAL_ZK_PROOF_VERIFICATION_FAILED };
      }
      const calldata = await groth16ExportSolidityCallData(
        proofAndSignals.proof, 
        proofAndSignals.publicSignals
      );

      const txResponse: WriteContractReturnType = await writeContract(this.config, {
        address,
        abi,
        functionName: "sellDkey",
        args: [dkey.formatCID(ipfsCID).ipfsCIDBytesString, this.myDKeys[chainId][ipfsCID].pubKeyX, this.myDKeys[chainId][ipfsCID].pubKeyY, calldata[0], calldata[1], calldata[2], calldata[3]],
        account: this.addresses[chainId as keyof typeof this.addresses] // throws error if user is not connected to this chain's saved address
      });
  
      const receipt = await waitForTransactionReceipt(this.config, {
        hash: txResponse,
      });
  
      if (receipt.status === "success") {
        delete this.myDKeys[chainId][ipfsCID];  
        return { success: true, profile: this, receipt, result: RESULTS.BLOCKCHAIN_INTERACTION_SUCCESSFUL };
      } else {
        return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
      }
    } catch (error: any) {
      console.error("Blockchain transaction failed:", error);
      return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
    }
  }

  /**
   * Allows a user to reclaim ETH from an open bid (i.e. no DKey was provided).
   * Deletes the bid from the user's profile upon success.
   * Must be called on the correct chain and from the original bidding address.
   *
   * @param ipfsCID - The IPFS CID of the listing associated with the bid.
   * @param chainId - The blockchain chain ID where the bid was placed.
   * @returns A promise resolving to a TransactionResult indicating success or failure, including the updated profile or error.
   */
  async reclaimBid(ipfsCID: string, chainId: number): Promise<TransactionResult> {
    const bid = this.myOpenBids[chainId][ipfsCID];

    const { address, abi } = contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2];
  
    try {
      const txResponse: WriteContractReturnType = await writeContract(this.config, {
        address,
        abi,
        functionName: "reclaimBid",
        args: [dkey.formatCID(ipfsCID).ipfsCIDBytesString, bid.pubKeyX, bid.pubKeyY],
        account: this.addresses[chainId as keyof typeof this.addresses] // throws error if user is not connected to this chain's saved address
      });
  
      const receipt: TransactionReceipt = await waitForTransactionReceipt(this.config, { hash: txResponse });
  
      if (receipt.status === "success") {
        delete this.myOpenBids[chainId][ipfsCID];
        return { success: true, profile: this, receipt, result: RESULTS.BLOCKCHAIN_INTERACTION_SUCCESSFUL };
      } else {
        return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
      }
    } catch (error: any) {
      console.error("Blockchain transaction failed:", error);
      return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
    }
  }

  /**
   * Increases the bid amount for an existing open bid.
   * Sends the additional ETH to the smart contract and --if successful-- updates the local bid record.
   *
   * @param ipfsCID - The IPFS CID of the listing associated with the bid.
   * @param chainId - The blockchain chain ID where the bid was placed.
   * @param increaseBidAmountInEth - The additional amount (in ETH) to add to the existing bid.
   * @returns A promise resolving to a TransactionResult indicating success or failure, including the updated profile or error.
   */
  async updateBid(ipfsCID: string, chainId: number, increaseBidAmountInEth: number): Promise<TransactionResult> {
    const bid = this.myOpenBids[chainId][ipfsCID];
    if (!bid) {
      return { success: false, result: RESULTS.BID_NOT_FOUND };
    }

    if (increaseBidAmountInEth <= 0) {
      return { success: false, result: RESULTS.INVALID_BID_AMOUNT };
    }

    const { address, abi } = contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2];
    const bigNumberWei = ethers.parseEther(increaseBidAmountInEth.toString());
    const bigIntWei = BigInt(bigNumberWei.toString());

    try {
      const txResponse: WriteContractReturnType = await writeContract(this.config, {
        address,
        abi,
        functionName: "updateBid",
        args: [dkey.formatCID(ipfsCID).ipfsCIDBytesString, [bid.pubKeyX, bid.pubKeyY]],
        value: bigIntWei,
        account: this.addresses[chainId as keyof typeof this.addresses]
      });

      const receipt: TransactionReceipt = await waitForTransactionReceipt(this.config, { hash: txResponse });

      if (receipt.status === "success") {
        this.myOpenBids[chainId][ipfsCID].increaseBidAmount(increaseBidAmountInEth);
        return { success: true, profile: this, receipt, result: RESULTS.BLOCKCHAIN_INTERACTION_SUCCESSFUL };
      } else {
        return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
      }
    } catch (error: any) {
      console.error("Blockchain transaction failed:", error);
      return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
    }
  }

  /**
   * Checks all owned DKeys on a specific chain to determine if they are eligible for resale.
   * Calls a batch read on the smart contract to check the can-sell status for each DKey.
   * Updates the local profile accordingly and returns a result indicating whether any changes were made.
   *
   * @param chainId - The chain ID on which to check the resale status of DKeys.
   * @returns A promise resolving to a TransactionResult indicating if any statuses were updated.
   */
  async checkIfDKeysCanBeSold(chainId: number): Promise<TransactionResult> {
    try {
      let updated = false;

      if (!this.myDKeys[chainId] || Object.keys(this.myDKeys[chainId]).length === 0) {
        return { success: true, profile: this, result: RESULTS.NO_UPDATES_TO_PROFILE };
      }

      const ipfsCidsToCheck = Object.values(this.myDKeys[chainId])
        .filter((dkey) => !dkey.canSell)
        .map((dkey) => dkey.ipfsCID);
  
      if (ipfsCidsToCheck.length === 0) {
        return { success: true, profile: this, result: RESULTS.NO_UPDATES_TO_PROFILE };
      }
  
      const ipfsCIDBytesArray = ipfsCidsToCheck.map(cid => dkey.formatCID(cid).ipfsCIDBytesString);
      console.log("ipfsCIDBytesArray", ipfsCIDBytesArray);
  
      const results: boolean[] = await readContract(this.config, {
        address: contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2].address,
        abi: contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2]?.abi,
        functionName: "batchCheckIfDkeysCanBeSold",
        args: [ipfsCIDBytesArray],
      }) as boolean[];

      ipfsCidsToCheck.forEach((cid, index) => {
        this.myDKeys[chainId][cid].canSell = results[index];

        if (results[index]) {
          updated = true;
        }
      });
      
      if (updated) {
        return { success: true, profile: this, result: RESULTS.PROFILE_UPDATED };
      } else {
        return { success: true, profile: this, result: RESULTS.NO_UPDATES_TO_PROFILE };
      }
    } catch (error) {
      console.error("Error checking if Dkeys can be sold:", error);
      return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
    }
  }

  /**
   * Checks the blockchain to see if any of the user's open bids on a given chain have been filled.
   * A bid is considered filled if the smart contract returns a max value for the bid amount.
   * Updates the local profile to mark such bids as filled.
   * 
   * NOTICE: even if a bid is marked as filled, still need to grab DKey[4] from blockchain event data (and call .dkeyReceived() on the profile)
   *
   * @param chainId - The blockchain chain ID to check for updated bid statuses.
   * @returns A promise resolving to a TransactionResult with the list of filled bid CIDs, or a no-op if none were updated.
   */
  async checkIfDKeysReceived(chainId: number): Promise<TransactionResult> {
    try {
      const openBids = Object.values(this.myOpenBids[chainId]);
      if (openBids.length === 0) {
        return { success: true, profile: this, result: RESULTS.NO_UPDATES_TO_PROFILE };
      }
  
      const ipfsCids = openBids.map((bid) => bid.ipfsCID);
      const bobPubKeyXs = openBids.map((bid) => bid.pubKeyX);
      const bobPubKeyYs = openBids.map((bid) => bid.pubKeyY);
      const ipfsCIDBytesArray = ipfsCids.map(cid => dkey.formatCID(cid).ipfsCIDBytesString);

      const bidAmounts: bigint[] = await readContract(this.config, {
        address: contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2].address,
        abi: contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2]?.abi,
        functionName: "batchGetBidStatuses",
        args: [ipfsCIDBytesArray, bobPubKeyXs, bobPubKeyYs],
      }) as bigint[];
  
      const filledBidCids = ipfsCids.filter((_, index) => bidAmounts[index] === BigInt("0xffffffffffffffffffffffff"));

      filledBidCids.forEach((cid, index) => {
        this.myOpenBids[chainId][cid].isFilled = true;
      });
  
      if (filledBidCids.length > 0) {
        return { success: true, profile: this, result: RESULTS.PROFILE_UPDATED };
      } else {
        return { success: true, profile: this, result: RESULTS.NO_UPDATES_TO_PROFILE };
      }
    } catch (error) {
      console.error("Error checking if bids have been filled:", error);
      return { success: false, result: RESULTS.BLOCKCHAIN_INTERACTION_FAILED };
    }
  }

  /**
   * Finalizes the receipt of a DKey after a successful bid, and saves it to `this.myDKeys`.
   * Decrypts the encrypted DKey using the user's secret key and adds it to their profile.
   * Removes the associated bid from the user's open bids.
   * 
   * NOTICE: front-end calls this after grabbing dKey[4] from the blockchain event data
   *
   * @param chainId - The chain ID where the DKey and bid were made.
   * @param ipfsCID - The IPFS Content Identifier of the listing.
   * @param dKey - A tuple containing four strings: [eM.x, eM.y, ke.x, ke.y] — the encrypted key points.
   * @returns The updated user profile with the new DKey added and bid removed.
   */
  async dkeyReceived(chainId: number, ipfsCID: string, dKey: [string, string, string, string]): Promise<this> {  
    if (!this.myDKeys[chainId]) {
      this.myDKeys[chainId] = {};
    }
  
    const bid = Object.values(this.myOpenBids[chainId]).find((b) => b.ipfsCID === ipfsCID);
    if (!bid) {
      throw new Error("No open bid found for this IPFS CID");
    }
  
    // Store encrypted dKey[4] values and secretKey instead of decrypting immediately
    const newDKey = new DKey(
      ipfsCID, 
      bid.bidderAddress, 
      bid.pubKeyX, 
      bid.pubKeyY, 
      dKey,  // Store [eM.x, eM.y, ke.x, ke.y] directly
      bid.secretKey,  // Store secretKey needed for decryption
      bid.fileName, 
      bid.chainId, 
      bid.bidAmountInEth
    );
    this.myDKeys[chainId][ipfsCID] = newDKey;

    console.log("New Dkey added to user profile:", this.myDKeys[chainId][ipfsCID]);
  
    delete this.myOpenBids[chainId][ipfsCID];
  
    return this;
  }

  /**
   * Fetches the Dkey from the blockchain event data.
   * 
   * @param chainId - The chain ID where the DKey and bid were made.
   * @param bid - The bid object.
   * @param bidBlockNumber - The block number where the bid was made.
   * @returns The updated user profile with the new DKey added and bid removed.
   */
  async fetchDkey(
    bid: Bid,
  ): Promise<TransactionResult> {
    const client = getPublicClient(this.config);
    if (!contracts.DKeyStoreL2[bid.chainId as keyof typeof contracts.DKeyStoreL2]) {
      return { success: false, result: RESULTS.UNSUPPORTED_CHAIN_ID };
    }

    const { address } = contracts.DKeyStoreL2[bid.chainId as keyof typeof contracts.DKeyStoreL2];
    const ipfsCIDBytesString = dkey.formatCID(bid.ipfsCID).ipfsCIDBytesString;

    if (typeof bid.bidBlockNumber !== "number" || !Number.isFinite(bid.bidBlockNumber) || bid.bidBlockNumber <= 0) {
      throw new Error("bidBlockNumber is required and must be a positive number");
    }

    const latest: bigint = await client.getBlockNumber();
    const floor: bigint = BigInt(bid.bidBlockNumber); // stop once we cross below this
    let toBlock: bigint = latest;
    const span: bigint = 5_000n; // tune as needed per RPC limits
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();

    while (toBlock >= floor) {
      let fromBlock: bigint = toBlock >= span ? toBlock - span + 1n : floor; // inclusive window
      if (fromBlock < floor) fromBlock = floor;

      const logs = await client.getLogs({
        address,
        fromBlock,
        toBlock,
        event: {
          type: 'event',
          name: 'DKeyProvided',
          inputs: [
            { type: 'bytes', indexed: true, name: 'ipfsCid' },
            { type: 'uint256', indexed: true, name: 'dkeyOwnerPubKeyX' },
            { type: 'uint256[4]', indexed: false, name: 'dKey' }
          ]
        },
        args: {
          ipfsCid: ipfsCIDBytesString as `0x${string}`,
          dkeyOwnerPubKeyX: BigInt(bid.pubKeyX)
        }
      });

      if (logs.length > 0) {
        // We are scanning newest->oldest; the last item is still the most recent in this window per ascending return order.
        const log = logs[logs.length - 1];
        const [dKeyArr] = abiCoder.decode(["uint256[4]"], log.data) as unknown as [readonly bigint[]];
        const dKeyTuple: [string, string, string, string] = [
          dKeyArr[0].toString(),
          dKeyArr[1].toString(),
          dKeyArr[2].toString(),
          dKeyArr[3].toString(),
        ];

        await this.dkeyReceived(bid.chainId, bid.ipfsCID, dKeyTuple);
        return { success: true, profile: this, result: RESULTS.PROFILE_UPDATED };
      }

      if (fromBlock === floor) break; // we've reached the bid block window and found nothing
      toBlock = fromBlock - 1n; // move the window down
    }

    return { success: false, result: RESULTS.DKEY_NOT_FOUND };
  }
  
  // checkers ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // view listing
  isDkeyOwner(ipfsCID: string, chainId: number): boolean {
    return !!this.myDKeys?.[chainId]?.[ipfsCID];
  }
  isListingOwner(ipfsCID: string, chainId: number): boolean {
    return !!this.myListings?.[chainId]?.[ipfsCID];
  }
  hasOpenBid(ipfsCID: string, chainId: number): boolean {
    return !!this.myOpenBids?.[chainId]?.[ipfsCID];
  }
  // profile
  hasOpenBids(): boolean {
    return Object.keys(this.myOpenBids).length > 0;
  }
  hasListings(): boolean {
    return Object.keys(this.myListings).length > 0;
  }
  hasDKeys(): boolean {
    return Object.keys(this.myDKeys).length > 0;
  }
  hasDkeyToFetch(chainId: number): boolean {
    return Object.keys(this.myOpenBids[chainId]).some((bid) => !this.myOpenBids[chainId][bid].isFilled);
  }

  // getters //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  getListing(ipfsCID: string, chainId: number): Listing {
    return this.myListings[chainId][ipfsCID];
  }
  getDKey(ipfsCID: string, chainId: number): DKey {
    return this.myDKeys[chainId][ipfsCID];
  }
  getArrayOfFilledBids(chainId: number): Bid[] {
    return Object.values(this.myOpenBids[chainId]).filter((bid) => bid.isFilled);
  }
  
  // profile serialization & encryption //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  /**
   * Serializes the current profile and encrypts it with the provided password.
   * Used for secure client-side storage (e.g., localStorage or file export).
   * @param password - The password used for AES encryption.
   * @returns A promise that resolves to an encrypted Blob containing the serialized profile.
   */
  toEncryptedProfileData(password: string): Promise<Blob> {
    const profileData = this.serialize();
    return aesEncrypt(profileData, password);
  }

  /**
   * Decrypts and deserializes profile data from an encrypted Blob using the provided password.
   * Reconstructs a DkeyUserProfile instance with proper class instances and provided config.
   * @param encryptedData - The encrypted profile data Blob.
   * @param password - The password used to decrypt the data.
   * @param config - The wagmi config to be passed to the new profile instance.
   * @returns A promise that resolves to a DkeyUserProfile instance.
   */
  static async fromEncryptedProfileData(encryptedData: Blob, password: string, config: any): Promise<DkeyUserProfile> {
    const encryptedDataArrayBuffer = await encryptedData.arrayBuffer();
    const profileData = await aesDecrypt(encryptedDataArrayBuffer, password);
    return DkeyUserProfile.deserialize(profileData, config);
  }
  
  
  /**
   * Serializes the current profile to a JSON string.
   * Used internally before encryption.
   * @returns A JSON string representation of the profile.
   */
  serialize(): string {
    return JSON.stringify({
      userInfo: this.userInfo,
      addresses: this.addresses,
      myListings: this.myListings,
      myDKeys: this.myDKeys,
      myOpenBids: this.myOpenBids,
    });
  }


  /**
   * Deserializes a JSON string into a DkeyUserProfile object.
   * Reconstructs all Listings, DKeys, and Bids into their proper class instances.
   * @param jsonString - The serialized profile data.
   * @param config - The wagmi config to be passed to the reconstructed profile.
   * @returns A DkeyUserProfile instance.
   */
  static deserialize(jsonString: string, config: any): DkeyUserProfile {
    const data = JSON.parse(jsonString);
  
    Object.keys(data.myListings).forEach((chainId) => {
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
        
        listing.howManyDKeysSold = listingData.howManyDKeysSold;
        listing.canDkeysBeSold = listingData.canDkeysBeSold;
        listing.pksThatHaveReceivedDkeys = listingData.pksThatHaveReceivedDkeys;
  
        data.myListings[chainId][ipfsCID] = listing;
      });
    });
  
    Object.keys(data.myDKeys).forEach((chainId) => {
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
  
        dkey.canSell = dkeyData.canSell;
        data.myDKeys[chainId][ipfsCID] = dkey;
      });
    });
  
    Object.keys(data.myOpenBids).forEach((chainId) => {
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
  
        bid.isFilled = bidData.isFilled;
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

// dkey obj ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Provides utility functions for file encryption, fetching listing details, and formatting.
 * Exposes library constants.
 */
const dkey = {
    constants,
    contracts,
    
      /**
     * Generates a BN254 key pair, encrypts the file using the public key, and returns the encrypted data and secret key.
     * @param data - The file content to encrypt.
     * @returns An object containing the encrypted data and key pair components.
     */
    createKeyAndEncryptFile: async (data: ArrayBuffer) => {
        const { secretKey, pubKeyX, pubKeyY } = constants.curve.createBN254KeyPair();
        const password = pubKeyX + pubKeyY;
        const encryptedData = await aesEncrypt(data, password);
        return { encryptedData, secretKeyX: pubKeyX, secretKeyY: pubKeyY };
    },

    /**
     * Fetches listing info from the smart contract and optionally appends open bids from the subgraph.
     * @param ipfsCID - The IPFS content identifier of the listing.
     * @param howManyBidsToFetch - Number of open bids to retrieve from the subgraph.
     * @param ListingMetadata - The metadata object associated with the listing (taken from IPFS).
     * @param config - The wagmi config for blockchain interaction.
     * @returns A detailed object describing the listing and its current bids.
     */
    fetchListingDetails: async (ipfsCID: string, ListingMetadata: ListingMetadata, config: any) => {
      const result = await readContract(config, {
          address: contracts.DKeyStoreL2[ListingMetadata.chainIds[0] as keyof typeof contracts.DKeyStoreL2].address,
          abi: contracts.DKeyStoreL2[ListingMetadata.chainIds[0] as keyof typeof contracts.DKeyStoreL2]?.abi,
          functionName: "getListingDetails",
          args: [dkey.formatCID(ipfsCID).ipfsCIDBytesString],
      });

      ///////////////////////////////////////////////////////////////
      // L2 only
      const totalBidsPlaced = await readContract(config, {
        address: contracts.DKeyStoreL2[ListingMetadata.chainIds[0] as keyof typeof contracts.DKeyStoreL2].address,
        abi: contracts.DKeyStoreL2[ListingMetadata.chainIds[0] as keyof typeof contracts.DKeyStoreL2]?.abi,
        functionName: "getTotalBidsPlaced",
        args: [dkey.formatCID(ipfsCID).ipfsCIDBytesString],
      }) as number;

      console.log("totalBidsPlaced index.ts: ", totalBidsPlaced);
      ///////////////////////////////////////////////////////////////

      const resultObj = result as {
        howManyDKeysForSale: any;
        howManyDKeysSold: any;
        royaltyPercentage: any;
        bidCounter: any;
        canDkeysBeSold: any;
        listingOwnerAddress: any;
      };

      const detailsObj = {
        howManyDKeysForSale: BigNumber(resultObj.howManyDKeysForSale!).toNumber(),
        howManyDKeysSold: BigNumber(resultObj.howManyDKeysSold!).toNumber(),
        priceInEth: ListingMetadata.suggestedPriceInEth,
        royaltyPercentage: BigNumber(resultObj.royaltyPercentage!).toNumber(),
        listingOwnerAddress: resultObj.listingOwnerAddress,
        canDkeysBeSold: resultObj.canDkeysBeSold,
        openBidsCounter: BigNumber(resultObj.bidCounter!).toNumber(),
        cidString: ipfsCID,
        fileName: ListingMetadata.fileName,
        description: ListingMetadata.fileDescription,
        fileSizeInBytes: ListingMetadata.fileSizeInBytes ?? undefined,  // Handle missing value
        seller: ListingMetadata.seller,
        coverPhotoLink: ListingMetadata.coverPhotoLink,
        coverPhotoCID: ListingMetadata.coverPhotoCID,
        chainIds: ListingMetadata.chainIds,
        bids: [],
        earliestBlockQueriedForBids: 0,
        listingCreatedAfterBlock: ListingMetadata.listingCreatedAfterBlock,
        totalBidsPlaced: totalBidsPlaced, // L2 only
      };

      return detailsObj;
    },

    // fetchBids: async (
    //   ipfsCID: string,
    //   chainId: number,
    //   numberOfBidsToFetch: number,
    //   config: any,
    //   listingCreatedAfterBlock?: number,
    //   startBlock?: number,
    //   blockIncrements?: number,
    // ) => {
    //   const bids: BidLite[] = [];
    //   let endBlock: bigint | undefined = undefined;

    //   if (numberOfBidsToFetch <= 0) {
    //     return { bids, endBlock };
    //   }

    //   const client = getPublicClient(config);
    //   if (!contracts[chainId as keyof typeof contracts]) {
    //     throw new Error("Unsupported chainId");
    //   }
    //   const { address, deploymentBlockNumber } = contracts[chainId as keyof typeof contracts];
    //   const ipfsCIDBytesString = dkey.formatCID(ipfsCID).ipfsCIDBytesString;

    //   // Establish initial toBlock
    //   let toBlock: bigint = typeof startBlock === "number" ? BigInt(startBlock) : await client.getBlockNumber();

    //   // Determine span (blocks per query)
    //   let span: bigint;
    //   if (typeof blockIncrements === "number" && blockIncrements > 0) {
    //     span = BigInt(blockIncrements);
    //   } else {
    //     span = BigInt(5000); // too big ?
    //   }

    //   const abiCoder = ethers.AbiCoder.defaultAbiCoder();

    //   // Work backwards in windows until we meet/exceed numberOfBidsToFetch or hit block 0
    //   while (true) {
    //     const fromBlock = toBlock > span ? toBlock - span : 0n;

    //     const logs = await client.getLogs({
    //       address,
    //       fromBlock,
    //       toBlock,
    //       event: {
    //         type: 'event',
    //         name: 'BidReceived',
    //         inputs: [
    //           { type: 'bytes', indexed: true, name: 'ipfsCID' },
    //           { type: 'uint256', indexed: false, name: 'bidNumber' },
    //           { type: 'uint256[2]', indexed: false, name: 'bidderDecryptingPubKey' },
    //           { type: 'uint256', indexed: false, name: 'bidAmount' }
    //         ]
    //       },
    //       args: {
    //         ipfsCID: ipfsCIDBytesString as `0x${string}`
    //       }
    //     });

    //     for (const log of logs) {
    //       // Decode non-indexed params: (bidNumber, bidderPubKey[2], bidAmount)
    //       const [bidNumberBn, bidderPubKeyArr, bidAmountBn] = abiCoder.decode(
    //         ["uint256", "uint256[2]", "uint256"],
    //         log.data
    //       );

    //       const bid = new BidLite(
    //         Number(bidNumberBn),
    //         ipfsCID,
    //         (bidderPubKeyArr as any[])[0].toString(),
    //         (bidderPubKeyArr as any[])[1].toString(),
    //         ethers.formatEther(bidAmountBn),
    //       );
    //       bids.push(bid);
    //     }

    //     // Stop once we've met/exceeded the target count; do NOT trim
    //     if (bids.length >= numberOfBidsToFetch) {
    //       endBlock = fromBlock;
    //       break;
    //     }

    //     // If we've reached the DKeyStore contract's deployment block OR the approximate block the listing was created on, we've gone too far
    //     if (fromBlock <= BigInt(deploymentBlockNumber)) {
    //       endBlock = BigInt(deploymentBlockNumber);
    //       break;
    //     }
    //     if (listingCreatedAfterBlock && fromBlock <= BigInt(listingCreatedAfterBlock)) {
    //       endBlock = BigInt(listingCreatedAfterBlock);
    //       break;
    //     }

    //     // Otherwise, step the window backward (`- 1n` avoids overlapping blocks)
    //     toBlock = fromBlock - 1n;
    //   }

    //   return { bids, endBlock };
    // },

    fetchBids: async (
      ipfsCID: string,
      chainId: number,
      config: any,
      listingCreatedAfterBlock: number,
      startAtBlock: number,
      endAtBlock: number,
      blockIncrements: number,
    ): Promise<BidLite[]> => {
      const bids: BidLite[] = [];
    
      const client = getPublicClient(config);
      if (!contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2]) {
        throw new Error("Unsupported chainId");
      }
      const { address, deploymentBlockNumber } = contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2];
      const ipfsCIDBytesString = dkey.formatCID(ipfsCID).ipfsCIDBytesString;
    
      const latest = await client.getBlockNumber();
      const beginAt = BigInt(startAtBlock);
      let toBlock = BigInt(endAtBlock) > latest ? latest : BigInt(endAtBlock);
      const span = BigInt(blockIncrements);
      if (span <= 0n) throw new Error("span must be > 0");
    
      // never scan before this floor
      const listingFloor = BigInt(listingCreatedAfterBlock || 0);
      const deployFloor = BigInt(deploymentBlockNumber || 0);
      const floor = [beginAt, listingFloor, deployFloor].reduce((a, b) => (a > b ? a : b));
      if (toBlock < floor) return bids;
    
      const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    
      // Work newest → oldest in inclusive windows, never before `floor`
      while (toBlock >= floor) {
        const fromBlock = toBlock >= floor + span - 1n ? toBlock - span + 1n : floor;
    
        const logs = await client.getLogs({
          address,
          fromBlock,
          toBlock,
          event: {
            type: "event",
            name: "BidReceived",
            inputs: [
              { type: "bytes", indexed: true, name: "ipfsCID" },
              { type: "uint256", indexed: false, name: "bidNumber" },
              { type: "uint256[2]", indexed: false, name: "bidderDecryptingPubKey" },
              { type: "uint256", indexed: false, name: "bidAmount" },
            ],
          },
          args: {
            ipfsCID: ipfsCIDBytesString as `0x${string}`,
          },
        });
    
        for (const log of logs) {
          const [bidNumberBn, bidderPubKeyArr, bidAmountBn] = abiCoder.decode(
            ["uint256", "uint256[2]", "uint256"],
            log.data
          );
    
          const bid = new BidLite(
            Number(bidNumberBn),
            ipfsCID,
            (bidderPubKeyArr as any[])[0].toString(),
            (bidderPubKeyArr as any[])[1].toString(),
            ethers.formatEther(bidAmountBn),
          );
          bids.push(bid);
        }
    
        if (fromBlock === floor) break; // reached lower bound
        toBlock = fromBlock - 1n; // step down without overlap
      }
    
      return bids;
    },

    fetchBidStatuses: async (chainId: number, bids: BidLite[], config: any) => {
      try {
        if (!contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2]) {
          throw new Error("Unsupported chainId");
        }
        if (!bids || bids.length === 0) {
          return [];
        }

        // Format arrays
        const ipfsCIDBytesArray = bids.map((b) => dkey.formatCID(b.ipfsCID).ipfsCIDBytesString);
        const pubKeyXs = bids.map((b) => b.pubKeyX);
        const pubKeyYs = bids.map((b) => b.pubKeyY);

        const { address, abi } = contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2];

        const amounts = await readContract(config, {
          address,  
          abi,
          functionName: "batchGetBidStatuses",
          args: [ipfsCIDBytesArray, pubKeyXs, pubKeyYs],
        }) as bigint[];

        bids.forEach((b, i) => {
          b.bidAmountInEth = ethers.formatEther(amounts[i]);
          b.isOpen = BigInt(amounts[i]) !== BigInt("0xffffffffffffffffffffffff") && BigInt(amounts[i]) !== BigInt("0");
        });

        return bids;
      } catch (err) {
        console.error("fetchBidStatuses error:", err);
        return [];
      }
    },

    fetchBidStatus: async (chainId: number, bid: BidLite, config: any): Promise<[Address, bigint]> => {
      if (!contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2]) {
        throw new Error("Unsupported chainId");
      }
      const { address, abi } = contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2];
      const ipfsCIDBytesString = dkey.formatCID(bid.ipfsCID).ipfsCIDBytesString;

      const result = await readContract(config, {
        address,
        abi,
        functionName: "getBidDetails",
        args: [ipfsCIDBytesString, bid.pubKeyX, bid.pubKeyY],
      }) as [Address, bigint];  // Tuple: [address, amount]

      return result;  // Return the full tuple
    },

    getCurrentBlock: async (config: any) => {
      const client = getPublicClient(config);
      return await client.getBlockNumber();
    },

    fetchOpenBids: async (
      chainId: number,
      ipfsCID: string,
      startingIndex: number,
      numberOfKeysToFetch: number,
      config: any
    ): Promise<[bigint, bigint, bigint][]> => {
      if (!contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2]) {
        throw new Error("Unsupported chainId");
      }
      const { address, abi } = contracts.DKeyStoreL2[chainId as keyof typeof contracts.DKeyStoreL2];
      const ipfsCIDBytesString = dkey.formatCID(ipfsCID).ipfsCIDBytesString;
    
      const result = await readContract(config, {
        address,
        abi,
        functionName: "getOpenBids",
        args: [ipfsCIDBytesString, startingIndex, numberOfKeysToFetch],
      }) as [bigint, bigint, bigint][];  // Array of [pubKeyX, pubKeyY, bidAmount] tuples
    
      return result;
    },

    // fetchDkey: async (chainId: number, bid: Bid, config: any, bidBlockNumber: number) => {
    //   const client = getPublicClient(config);
    //   if (!contracts[chainId as keyof typeof contracts]) {
    //     throw new Error("Unsupported chainId");
    //   }

    //   const { address, deploymentBlockNumber } = contracts[chainId as keyof typeof contracts];
    //   const ipfsCIDBytesString = dkey.formatCID(bid.ipfsCID).ipfsCIDBytesString;

    //   // Require bidBlockNumber and set it as the lower bound for scanning
    //   if (typeof bidBlockNumber !== "number" || !Number.isFinite(bidBlockNumber) || bidBlockNumber <= 0) {
    //     throw new Error("bidBlockNumber is required and must be a positive number");
    //   }
    //   let toBlock: bigint = BigInt(bidBlockNumber);

    //   // Scan window size (blocks per query)
    //   let span: bigint = 5000n;

    //   const abiCoder = ethers.AbiCoder.defaultAbiCoder();

    //   while (true) {
    //     // Never scan earlier than bidBlockNumber
    //     const minBlock = BigInt(bidBlockNumber);
    //     const fromBlock = toBlock > span ? (toBlock - span > minBlock ? toBlock - span : minBlock) : minBlock;

    //     // Query logs for the DKeyProvided event filtered by cid and owner's pubKeyX
    //     const logs = await client.getLogs({
    //       address,
    //       fromBlock,
    //       toBlock,
    //       event: {
    //         type: 'event',
    //         name: 'DKeyProvided',
    //         inputs: [
    //           { type: 'bytes', indexed: true, name: 'ipfsCid' },
    //           { type: 'uint256', indexed: true, name: 'dkeyOwnerPubKeyX' },
    //           { type: 'uint256[4]', indexed: false, name: 'dKey' }
    //         ]
    //       },
    //       args: {
    //         ipfsCid: ipfsCIDBytesString as `0x${string}`,
    //         dkeyOwnerPubKeyX: BigInt(bid.pubKeyX)
    //       }
    //     });

    //     if (logs.length > 0) {
    //       // Decode the only non-indexed arg: dKey (uint256[4])
    //       // If multiple logs are found in the window, prefer the most recent one
    //       const log = logs[logs.length - 1];
    //       const [dKeyArr] = abiCoder.decode(["uint256[4]"], log.data) as unknown as [readonly bigint[]];
    //       const dKeyTuple: [string, string, string, string] = [
    //         dKeyArr[0].toString(),
    //         dKeyArr[1].toString(),
    //         dKeyArr[2].toString(),
    //         dKeyArr[3].toString(),
    //       ];

    //       return {
    //         dKey: dKeyTuple,
    //       } as { dKey: [string, string, string, string] };
    //     }

    //     // Stop if we've reached or passed the bidBlockNumber
    //     if (fromBlock <= BigInt(bidBlockNumber)) {
    //       break;
    //     }

    //     // Step the window backward (`- 1n` avoids re-scanning the boundary block)
    //     toBlock = fromBlock - 1n;
    //   }

    //   // If not found, return null to signal the caller to expand search parameters or handle accordingly
    //   return null;
    // },

    /**
     * Formats an IPFS CID into multiple representations: bytes, hex string, and hashed string.
     * @param cid - The IPFS CID to format.
     * @returns An object containing multiple representations of the CID.
     */
    formatCID: (cid: string): { ipfsCIDBytes: Uint8Array; ipfsCIDBytesString: string; hashedCid0xString: `0x${string}`; hashedCidString: string } => {
        const parsedCid = CID.parse(cid, base32);
        const bytes32CID = parsedCid.bytes.slice(4);
        const ipfsCIDBytes = ethers.getBytes(bytes32CID);
        const ipfsCIDBytesString = ethers.hexlify(ipfsCIDBytes);
        const hashedCid0xString = keccak256(ipfsCIDBytes); // FYI: this format is how subgraph references ipfsCIDs
        const hashedCidString = keccak256(ipfsCIDBytes).toString();
        
        return {
            ipfsCIDBytes,
            ipfsCIDBytesString,
            hashedCid0xString,
            hashedCidString,
        };
    },

    /**
     * Generates an HSL color based on the last 6 characters of the IPFS CID.
     * @param ipfsCID - The IPFS content identifier.
     * @returns A CSS HSL color string.
     */
    getRGBColorFromCID: (ipfsCID: string) => {
        const cidLastSix = ipfsCID.slice(-6);
        const color = cidLastSix.split('').reduce((acc: number, char: string) => acc + char.charCodeAt(0), 0) % 360;
        return `hsl(${color}, 70%, 50%)`;
    },

    /**
     * Dynamically loads the SnarkJS script in the browser environment. 
     * Script does not seem able to be imported.
     * Used for client-side ZK proof generation.
     * @returns A promise that resolves when the script is loaded.
     */
    loadSnarkJS: async () => {
      if (typeof window === "undefined") return;
    
      return new Promise<void>((resolve) => {
        const script = document.createElement("script");
        script.src = "/snarkjs.min.js";
        script.async = true;
        script.onload = () => resolve();
        document.body.appendChild(script);
      });
    }
};
  
export default dkey;
export { DkeyUserProfile, Listing, ListingMetadata, Bid, DKey, dkey, RESULTS, BidLite };
