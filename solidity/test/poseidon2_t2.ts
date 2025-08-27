import { describe, it } from "node:test";
import { expect } from "chai";
import { network } from "hardhat";

describe("Poseidon2", async function () {
  const { viem } = await network.connect();
  const publicClient = await viem.getPublicClient();

  it("Poseidon2 t2 compression kat", async function () {
  const poseidon2_lib = await viem.deployContract("contracts/poseidon2_t2.sol:Poseidon2T2");
  console.log("Poseidon2T2 deployed to:", poseidon2_lib.address);
  const poseidon2_lib_opt = await viem.deployContract("contracts/poseidon2_t2_opt.sol:Poseidon2T2opt");
  console.log("Poseidon2T2opt deployed to:", poseidon2_lib_opt.address);

  const poseidon2 = await viem.deployContract("Poseidon2", undefined, {libraries: {
        "Poseidon2T2": poseidon2_lib.address, "Poseidon2T2opt": poseidon2_lib_opt.address
      }});

  console.log("Running Poseidon2 t2 compression kat...");
  const hash1 = await poseidon2.write.compress([[BigInt(0),BigInt(1)]]);
  const stats1 = await publicClient.waitForTransactionReceipt({ hash: hash1 });
  const res1 = await poseidon2.read.result();
  expect(res1).to.be.equal(BigInt("0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878b"));
  console.log("...done");
  console.log("Gas used:", stats1.gasUsed);

  console.log("Running Poseidon2 t2 opt compression kat...");
  const hash2 = await poseidon2.write.compress_opt([[BigInt(0),BigInt(1)]]);
  const stats2 = await publicClient.waitForTransactionReceipt({ hash: hash2 });
  const res2 = await poseidon2.read.result();
  expect(res2).to.be.equal(BigInt("0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878b"));
  console.log("...done");
  console.log("Gas used:", stats2.gasUsed);
  });
});
