import { beforeAll, afterAll, expect, test, describe } from "bun:test";
import { join } from "path";
import { $ } from "bun";
import { readLogFromDisk } from "../src/utils";
import { resolveDIDFromLog } from "../src/method";
import { generateTestVerificationMethod } from './utils';
import type { VerificationMethod } from "../src/interfaces";

// Set environment variables for tests
process.env.IGNORE_ASSERTION_KEY_IS_AUTHORIZED = 'true';
process.env.IGNORE_ASSERTION_NEW_KEYS_ARE_VALID = 'true';
process.env.IGNORE_ASSERTION_DOCUMENT_STATE_IS_VALID = 'true';

const TEST_DIR = join(process.cwd(), 'test', 'temp-cli-e2e');

beforeAll(async () => {
  await $`mkdir -p ${TEST_DIR}`.quiet();
});

afterAll(async () => {
  await $`rm -rf ${TEST_DIR}`.quiet();
});

// Helper function to create a temporary verification method file for CLI commands
async function createTempVerificationMethod(vm: VerificationMethod): Promise<string> {
  const tempFile = join(TEST_DIR, `vm-${Date.now()}.json`);
  const vmData = Buffer.from(JSON.stringify([vm])).toString('base64');
  await Bun.write(tempFile, vmData);
  return tempFile;
}

describe("CLI End-to-End Tests", async () => {
  test("Create DID using CLI", async () => {
    const proc = await $`bun run cli create --domain example.com --output ${join(TEST_DIR, 'did.jsonl')} --portable`.quiet();
    expect(proc.exitCode).toBe(0);
    expect(proc.stdout.toString()).toContain('Created DID');
  });

  test("Update DID using CLI", async () => {
    const logFile = join(TEST_DIR, 'did-update.jsonl');
    
    // First create a DID with a test verification method
    const vm = await generateTestVerificationMethod();
    const vmFile = await createTempVerificationMethod(vm);
    
    const createProc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli create --domain example.com --output ${logFile} --portable`.quiet();
    expect(createProc.exitCode).toBe(0);
    
    // Update the DID
    const updateProc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli update --log ${logFile} --output ${logFile} --update-key z1A2b3C4d5E6f7G8h9I0j`.quiet();
    expect(updateProc.exitCode).toBe(0);
    
    // Verify the update was successful
    const log = await readLogFromDisk(logFile);
    expect(log).toHaveLength(2);
    
    // Clean up
    await $`rm ${vmFile}`.quiet();
  });

  test("Second Update DID using CLI", async () => {
    const logFile = join(TEST_DIR, 'did-update2.jsonl');
    
    // Create a DID with a test verification method
    const vm = await generateTestVerificationMethod();
    const vmFile = await createTempVerificationMethod(vm);
    
    const createProc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli create --domain example.com --output ${logFile} --portable`.quiet();
    expect(createProc.exitCode).toBe(0);
    
    // First update
    const update1Proc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli update --log ${logFile} --output ${logFile} --update-key z1A2b3C4d5E6f7G8h9I0j`.quiet();
    expect(update1Proc.exitCode).toBe(0);
    
    // Second update
    const update2Proc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli update --log ${logFile} --output ${logFile} --update-key z2B3c4D5e6F7g8H9i0K1l`.quiet();
    expect(update2Proc.exitCode).toBe(0);
    
    // Verify the updates were successful
    const log = await readLogFromDisk(logFile);
    expect(log).toHaveLength(3);
    
    // Clean up
    await $`rm ${vmFile}`.quiet();
  });

  test("Deactivate DID using CLI", async () => {
    const logFile = join(TEST_DIR, 'did-deactivate.jsonl');
    
    // Create a DID with a test verification method
    const vm = await generateTestVerificationMethod();
    const vmFile = await createTempVerificationMethod(vm);
    
    const createProc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli create --domain example.com --output ${logFile} --portable`.quiet();
    expect(createProc.exitCode).toBe(0);
    
    // Deactivate the DID
    const deactivateProc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli deactivate --log ${logFile} --output ${logFile}`.quiet();
    expect(deactivateProc.exitCode).toBe(0);
    
    // Verify deactivation
    const log = await readLogFromDisk(logFile);
    const { meta } = await resolveDIDFromLog(log);
    expect(meta.deactivated).toBe(true);
    
    // Clean up
    await $`rm ${vmFile}`.quiet();
  });

  test("Create DID with prerotation", async () => {
    const prerotationLogFile = join(TEST_DIR, 'did-prerotation.jsonl');
    const nextKeyHash1 = 'nextKey1Hash';
    const nextKeyHash2 = 'nextKey2Hash';
    
    const proc = await $`bun run cli create --domain example.com --output ${prerotationLogFile} --portable --next-key-hash ${nextKeyHash1} --next-key-hash ${nextKeyHash2}`.quiet();
    expect(proc.exitCode).toBe(0);
    
    // Wait a moment for the file to be written
    await new Promise(resolve => setTimeout(resolve, 100));

    // Get the current authorized key and DID
    const currentLog = await readLogFromDisk(prerotationLogFile);
    const { did, meta } = await resolveDIDFromLog(currentLog);
    const authorizedKey = meta.updateKeys[0];
    
    // Verify nextKeyHashes setup
    expect(currentLog[0].parameters.nextKeyHashes).toHaveLength(2);
    expect(currentLog[0].parameters.nextKeyHashes).toContain(nextKeyHash1);
    expect(currentLog[0].parameters.nextKeyHashes).toContain(nextKeyHash2);
  });

  test("Update DID with verification methods", async () => {
    const vmLogFile = join(TEST_DIR, 'did-vm.jsonl');
    
    // Create a DID with a test verification method
    const vm = await generateTestVerificationMethod();
    const vmFile = await createTempVerificationMethod(vm);
    
    const createProc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli create --domain example.com --output ${vmLogFile} --portable`.quiet();
    expect(createProc.exitCode).toBe(0);
    
    // Wait a moment for the file to be written
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Get the DID
    const initialLog = await readLogFromDisk(vmLogFile);
    const { did } = await resolveDIDFromLog(initialLog);

    // Add all VM types in a single update
    const proc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli update --log ${vmLogFile} --output ${vmLogFile} --add-vm authentication --add-vm assertionMethod --add-vm keyAgreement --add-vm capabilityInvocation --add-vm capabilityDelegation`.quiet();
    expect(proc.exitCode).toBe(0);
    
    // Verify all VM types were added
    const finalLog = await readLogFromDisk(vmLogFile);
    const finalEntry = finalLog[finalLog.length - 1];
    
    // Get the authorized key from the final state
    const { meta: finalMeta } = await resolveDIDFromLog(finalLog);
    const authorizedKey = finalMeta.updateKeys[0];
    
    const vmTypes = ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'] as const;
    const vmId = `${did}#${authorizedKey.slice(-8)}`;
    
    for (const vmType of vmTypes) {
        expect(finalEntry.state[vmType]).toBeDefined();
        expect(Array.isArray(finalEntry.state[vmType])).toBe(true);
        expect(finalEntry.state[vmType]).toContain(vmId);
    }
    
    // Clean up
    await $`rm ${vmFile}`.quiet();
  });

  test("Update DID with alsoKnownAs", async () => {
    const akLogFile = join(TEST_DIR, 'did-aka.jsonl');
    
    // Create a DID with a test verification method
    const vm = await generateTestVerificationMethod();
    const vmFile = await createTempVerificationMethod(vm);
    
    const createProc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli create --domain example.com --output ${akLogFile} --portable`.quiet();
    expect(createProc.exitCode).toBe(0);
    
    // Wait a moment for the file to be written
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Get the current authorized key and DID
    const currentLog = await readLogFromDisk(akLogFile);
    const { did, meta } = await resolveDIDFromLog(currentLog);
    const authorizedKey = meta.updateKeys[0];

    // Update with alsoKnownAs
    const alias = 'https://example.com/users/123';
    const proc = await $`DID_VERIFICATION_METHODS=$(cat ${vmFile}) bun run cli update --log ${akLogFile} --output ${akLogFile} --also-known-as ${alias}`.quiet();
    expect(proc.exitCode).toBe(0);
    
    // Verify alsoKnownAs was added
    const finalLog = await readLogFromDisk(akLogFile);
    const finalEntry = finalLog[finalLog.length - 1];
    
    expect(finalEntry.state.alsoKnownAs).toBeDefined();
    expect(Array.isArray(finalEntry.state.alsoKnownAs)).toBe(true);
    expect(finalEntry.state.alsoKnownAs).toContain(alias);
    
    // Clean up
    await $`rm ${vmFile}`.quiet();
  });

  test("Resolve DID command", async () => {
    // First create a DID
    const resolveLogFile = join(TEST_DIR, 'did-resolve.jsonl');
    const createProc = await $`bun run cli create --domain example.com --output ${resolveLogFile} --portable`.quiet();
    expect(createProc.exitCode).toBe(0);
    
    // Get the DID from the log
    const log = await readLogFromDisk(resolveLogFile);
    const { did } = await resolveDIDFromLog(log);
    
    // Test resolve command with log file instead of DID
    const proc = await $`bun run cli resolve --log ${resolveLogFile}`.quiet();
    expect(proc.exitCode).toBe(0);
    
    // Verify resolve output contains expected fields
    const output = proc.stdout.toString();
    expect(output).toContain('Resolved DID');
    expect(output).toContain('DID Document');
    expect(output).toContain('Metadata');
  });
}); 

describe("Witness CLI End-to-End Tests", async () => {
  test("Create DID with witnesses using CLI", async () => {
    const logFile = join(TEST_DIR, 'did.jsonl');
    
    try {
      // Use the test implementation instead of generateEd25519VerificationMethod
      const witness = await generateTestVerificationMethod();
      // Parse the witness log and get the verification key from the state
      const witnessDIDKey = `did:key:${witness.publicKeyMultibase}#${witness.publicKeyMultibase}`;
      
      // Run the CLI create command with witness
      const proc = await $`bun run cli create --domain localhost:8000 --output ${logFile} --witness ${witnessDIDKey} --witness-threshold 1`.quiet();

      expect(proc.exitCode).toBe(0);
      
      // Verify the witness configuration
      const log = await readLogFromDisk(logFile);
      
      // Add null checks for TypeScript
      if (!log[0]?.parameters?.witness) {
        throw new Error('Witness configuration not found in DID log');
      }
      
      expect(log[0].parameters.witness.witnesses).toHaveLength(1);
      expect(log[0].parameters.witness.witnesses?.[0]?.id).toBe(witnessDIDKey);
      expect(log[0].parameters.witness.threshold).toBe(1);
    } catch (error) {
      console.error('Error in witness test:', error);
      throw error;
    }
  });
});
