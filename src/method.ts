import { fetchLogFromIdentifier, getActiveDIDs } from "./utils";
import type { CreateDIDInterface, DIDLog, UpdateDIDInterface, DeactivateDIDInterface, ResolutionOptions, WitnessProofFileEntry } from './interfaces';
import * as v1 from './method_versions/method.v1.0';
import * as v0_5 from './method_versions/method.v0.5';


function getWebvhVersionFromMethod(method?: string): string {
  if (!method) return '1.0';
  const match = method.match(/^did:webvh:(\d+\.\d+)$/);
  return match ? match[1] : '1.0';
}

function getWebvhVersionFromLog(log: DIDLog): string {
  if (log && log.length > 0 && log[0].parameters && log[0].parameters.method) {
    return getWebvhVersionFromMethod(log[0].parameters.method);
  }
  return '1.0';
}

function getWebvhVersionFromOptions(options: any): string {
  if (options && options.method) {
    return getWebvhVersionFromMethod(options.method);
  }
  return '1.0';
}

export const createDID = async (options: CreateDIDInterface) => {
  const version = getWebvhVersionFromOptions(options);
  if (version === '0.5') {
    return v0_5.createDID(options);
  }
  return v1.createDID(options);
};

export const resolveDID = async (did: string, options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}) => {
  const activeDIDs = await getActiveDIDs();
  const controlled = activeDIDs.includes(did);
  try {
    const log = await fetchLogFromIdentifier(did, controlled);
    const version = getWebvhVersionFromLog(log);
    if (version === '0.5') {
      const result = await v0_5.resolveDIDFromLog(log, options);
      return { ...result, controlled };
    }
    const result = await v1.resolveDIDFromLog(log, options);
    return { ...result, controlled };
  } catch (e: any) {
    let errorType: 'notFound' | 'invalidDid' = 'invalidDid';
    const message = e instanceof Error ? e.message : String(e);
    if (/not found/i.test(message) || /404/.test(message)) {
      errorType = 'notFound';
    }
    return {
      did,
      doc: null,
      meta: {
        error: errorType,
        problemDetails: {
          type: errorType === 'notFound'
            ? 'https://w3id.org/security#NOT_FOUND'
            : 'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID',
          title: errorType === 'notFound'
            ? 'The DID Log or resource was not found.'
            : 'The resolved DID is invalid.',
          detail: message
        }
      },
      controlled
    };
  }
};

export const resolveDIDFromLog = async (log: DIDLog, options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}) => {
  const version = getWebvhVersionFromLog(log);
  if (version === '0.5') {
    return v0_5.resolveDIDFromLog(log, options);
  }
  return v1.resolveDIDFromLog(log, options);
};

export const updateDID = async (options: UpdateDIDInterface & { services?: any[], domain?: string, updated?: string }) => {
  const version = options.log ? getWebvhVersionFromLog(options.log) : getWebvhVersionFromOptions(options);
  if (version === '0.5') {
    return v0_5.updateDID(options);
  }
  return v1.updateDID(options);
};

export const deactivateDID = async (options: DeactivateDIDInterface & { updateKeys?: string[] }) => {
  const version = options.log ? getWebvhVersionFromLog(options.log) : getWebvhVersionFromOptions(options);
  if (version === '0.5') {
    return v0_5.deactivateDID(options);
  }
  return v1.deactivateDID(options);
};
