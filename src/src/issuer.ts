import fs from "fs";
import { generateBls12381G2KeyPair, blsSign, blsCreateProof, blsVerifyProof } from "@mattrglobal/bbs-signatures";

const issuedDir = "./issued";
if (!fs.existsSync(issuedDir)) fs.mkdirSync(issuedDir);

const command = process.argv[2];

if (!command) {
  console.log("Usage: npm run cli -- [issue|present|verify]");
  process.exit(1);
}

const timestamp = Date.now();

switch (command) {

  case "issue":
    (async () => {
      console.log("=== ISSUER ===");

      const keyPair = await generateBls12381G2KeyPair();
      const credential = {
        "@context": ["https://w3id.org/security/bbs/v1"],
        type: ["VerifiableCredential", "IdentityCredential"],
        issuer: "did:example:issuer123",
        credentialSubject: {
          name: "Siddharth Gautam",
          age: 22,
          university: "DSCE"
        }
      };

      const messages = Object.values(credential.credentialSubject)
        .map(s => new TextEncoder().encode(String(s)));

      const signature = await blsSign({ keyPair, messages });

      const credFile = `${issuedDir}/cred-${timestamp}.json`;
      fs.writeFileSync(credFile, JSON.stringify({ credential, signature, publicKey: keyPair.publicKey }, null, 2));
      console.log("✅ Credential issued and saved to", credFile);
    })();
    break;

  case "present":
    (async () => {
      console.log("=== HOLDER ===");

      const files = fs.readdirSync(issuedDir).filter(f => f.startsWith("cred-"));
      if (files.length === 0) { console.error("No credentials found!"); process.exit(1); }
      const latest = files.sort().reverse()[0];
      const issued = JSON.parse(fs.readFileSync(`${issuedDir}/${latest}`, "utf-8"));
      const { credential, signature, publicKey } = issued;

      const messages = Object.values(credential.credentialSubject)
        .map(s => new TextEncoder().encode(String(s)));

      const revealIndices = [1]; // reveal 'age' only
      const proof = await blsCreateProof({ signature, publicKey, messages, reveal: revealIndices });

      const proofFile = `${issuedDir}/proof-${timestamp}.json`;
      fs.writeFileSync(proofFile, JSON.stringify({
        revealed: { age: credential.credentialSubject.age },
        proof,
        publicKey
      }, null, 2));

      console.log("✅ Proof created and saved to", proofFile);
    })();
    break;

  case "verify":
    (async () => {
      console.log("=== VERIFIER ===");

      const files = fs.readdirSync(issuedDir).filter(f => f.startsWith("proof-"));
      if (files.length === 0) { console.error("No proofs found!"); process.exit(1); }
      const latest = files.sort().reverse()[0];
      const proofFile = JSON.parse(fs.readFileSync(`${issuedDir}/${latest}`, "utf-8"));
      const { proof, publicKey, revealed } = proofFile;

      const result = await blsVerifyProof({ proof, publicKey });

      console.log("✅ Proof valid:", result.verified);
      console.log("Revealed fields:", revealed);
    })();
    break;

  default:
    console.log("Unknown command. Use: issue | present | verify");
    process.exit(1);
}
