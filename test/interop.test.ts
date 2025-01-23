import { describe, expect, test } from "bun:test";
import { resolveDID } from "../src/method";

describe("did:webvh interoperability tests", async () => {
  test("anywhy.ca", async () => {
    const did = "did:webvh:QmU55yaLrkhCaTsmBgEqRiUTT6zGtxSZfvJS8vWQM4tgDb:anywhy.ca:webvh-05";
    const {did: resolvedDID, meta} = await resolveDID(did);
    expect(resolvedDID).toBe(did);
    expect(meta.nextKeyHashes.length).toBeGreaterThan(0);
    expect(meta.prerotation).toBe(true);
    expect(meta.portable).toBe(false);
    expect(meta.witness?.witnesses.length).toBe(3);
  })

  test("anywhy.ca large", async () => {
    const did = "did:webvh:QmahiuqDheWp6ZgRC66fsthiALqBFxvYQKk8uTQeqaBUQ2:anywhy.ca:webvh-05-large";
    const {did: resolvedDID, meta} = await resolveDID(did);
    expect(resolvedDID).toBe(did);
    expect(meta.nextKeyHashes.length).toBeGreaterThan(0);
    expect(meta.prerotation).toBe(true);
    expect(meta.portable).toBe(false);
    expect(meta.witness?.witnesses.length).toBe(3);
  })

  test.skip("demo.identifier.me", async () => {
    const did = "did:tdw:QmbkyrrjFQ3Z2WiDfmesKpmeUhemaiqkWgwemovmVaTJfQ:demo.identifier.me:client:c9dd16b7-e079-43da-b0a9-36515e726c6f";
    const {did: resolvedDID, meta} = await resolveDID(did);
    expect(resolvedDID).toBe(did);
    expect(meta.prerotation).toBe(false);
    expect(meta.portable).toBe(false);
  })

  test.skip("gist", async () => {
    const did = "did:webvh:QmbnQXj7DhWFrmgjDPKZCybn8fkKW7Wze57SQHpwsSQ7NZ:gist.githubusercontent.com:brianorwhatever:9c4633d18eb644f7a47f93a802691626:raw";
    const {did: resolvedDID, meta} = await resolveDID(did);
    expect(resolvedDID).toBe(did);
    expect(meta.prerotation).toBe(false);
    expect(meta.portable).toBe(false);
  })
});
