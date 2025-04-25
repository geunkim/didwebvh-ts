export { resolveDID, resolveDIDFromLog, createDID, updateDID, deactivateDID } from './method';
export { createDocumentSigner, prepareDataForSigning, createProof, createSigner, AbstractCrypto } from './cryptography';
export * from './interfaces';
export { multibaseEncode, multibaseDecode, MultibaseEncoding } from './utils/multiformats';