const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

const a_x =
  17198511433894968793465431674681704063214539090234231940658916129372939658280n;
const a_y =
  7096022295031894750538718201677443509070855497286293707399348308180894474126n;
const b_x =
  1370195182723755180330139957608574837756381581331631262925562351487402786675n;
const b_y =
  4914841023884182990424920031862777928930597684365442051411609356476877989803n;

describe("BabyJubJub Check Correct Subgroup", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/check_correct_subgroup_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("A is correct subgroup", async () => {
    const witness = await circuit.calculateWitness({ in: [a_x, a_y] }, true);
    await circuit.checkConstraints(witness);
  });

  it("B is correct subgroup", async () => {
    const witness = await circuit.calculateWitness({ in: [b_x, b_y] }, true);
    await circuit.checkConstraints(witness);
  });

  it("Infinity is correct subgroup", async () => {
    const witness = await circuit.calculateWitness({ in: [0, 1] }, true);
    await circuit.checkConstraints(witness);
  });

  it("Random point not correct subgroup", async () => {
    var did_fail = false;
    try {
      await circuit.calculateWitness({ in: [a_x, b_x] }, true);
    } catch (e) {
      did_fail = true;
    }
    expect(did_fail).to.be.true;
  });
});
