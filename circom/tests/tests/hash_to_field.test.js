const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("hash to field Poseidon2 t=3", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/hash_to_field_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("kat0", async () => {
    const witness = await circuit.calculateWitness({ in: [42] }, true);
    await circuit.assertOut(witness, {
      out: 0x2e5c8c8ff53da47080c341f261d1a10c1d54f6650b90bbed9dd30198ca1256b3n,
    });
    await circuit.checkConstraints(witness);
  });
});
