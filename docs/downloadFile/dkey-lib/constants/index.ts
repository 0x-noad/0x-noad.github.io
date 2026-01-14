const elgamal = require("../EC-ElGamal/build/elgamal.ts");

const Point = elgamal.Point;
const G = elgamal.G;
const fp = elgamal.fp;
const getInRange = elgamal.getInRange;
const createBN254KeyPair = () => {
    let [secret, pub] = elgamal.key_pair();
    const secretKey = secret.toString();
    const pubKeyX = pub.px.toString();
    const pubKeyY = pub.py.toString();
    return { secretKey, pubKeyX, pubKeyY };
}

const circuit = {
    wasmFile: "/circuits/encryptAndHash_js/encryptAndHash.wasm",
    zkeyFile: "/circuits/encryptAndHash_js/encryptAndHash_0001.zkey",
    verificationKey: "/circuits/encryptAndHash_js/verification_key.json",
};

// const batchCircuit = {
//     wasmFile: "/circuits/encryptAndHashBatch_js/encryptAndHashBatch.wasm",
//     zkeyFile: "/circuits/encryptAndHashBatch_js/circuit_final.zkey",
//     verificationKey: "/circuits/encryptAndHashBatch_js/verification_key.json",
// };

const URLs = {
    [31337]: {
        subgraph: "http://localhost:8000/subgraphs/name/scaffold-eth/dkey",
    },
};

const queries = {
    GetBids: `query GetBids($listingId: ID!, $first: Int!) {
        listing(id: $listingId) {
            id
            bids(
                where: { isOpen: true }
                first: $first
                orderBy: amount
                orderDirection: desc
            ) {
                id
                ethAddress
                amount
                bidderPubKeyX
                bidderPubKeyY
            }
        }
    }`,
    GetBidDetails: `query GetBidDetails($bidId: ID!) {
        bid(id: $bidId) {
            isOpen
            dKey1
            dKey2
            dKey3
            dKey4
        }
    }`,
    GetDetailsForMultipleBids: `query GetDetailsForMultipleBids($bidIds: [ID!]!) {
        bids(where: { id_in: $bidIds }) {
            id
            isOpen
            dKey1
            dKey2
            dKey3
            dKey4
        }
    }`,
};

export const constants = {
    curve: { G, fp, getInRange, Point, createBN254KeyPair },
    circuit,
    // batchCircuit,
    URLs,
    queries,
};

export default constants;