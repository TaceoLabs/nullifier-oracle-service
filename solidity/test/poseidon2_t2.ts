// We don't have Ethereum specific assertions in Hardhat 3 yet
import { describe, it } from "node:test";
import { expect } from "chai";
import { network } from "hardhat";

describe("Poseidon2", async function () {
  const { viem } = await network.connect();

  it("Poseidon2 t2 compression kat", async function () {
  const poseidon2_lib = await viem.deployContract("contracts/poseidon2_t2.sol:Poseidon2T2");
  const poseidon2_lib_opt = await viem.deployContract("contracts/poseidon2_t2_opt.sol:Poseidon2T2opt");

    const poseidon2 = await viem.deployContract("Poseidon2", undefined, {libraries: {
        "Poseidon2T2": poseidon2_lib.address, "Poseidon2T2opt": poseidon2_lib_opt.address
      }});
    expect(await poseidon2.read.compress([[BigInt(0),BigInt(1)]])).to.be.equal(BigInt(0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878b));

    expect(await poseidon2.read.compress_opt([[BigInt(0),BigInt(1)]])).to.be.equal(BigInt(0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878b));
  });

});
