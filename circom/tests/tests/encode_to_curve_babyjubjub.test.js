const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("encode to curve babyjubjub", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/encode_to_curve_babyjubjub_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });

  it("encode 0", async () => {
    const witness = await circuit.calculateWitness({ in: 0 }, true);
    await circuit.assertOut(witness, {
      out: [
        20933827970802813890983825285326248243008219406120265623912040617116488051168n,
        19221830974981021604074333064965073057369542973805695443932626741929482323481n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("encode 1", async () => {
    const witness = await circuit.calculateWitness({ in: 1 }, true);
    await circuit.assertOut(witness, {
      out: [
        158003743186178317583285349076672373866032857213932356251773095567170960213n,
        4814651661221091094003361804145731078627371241787264107209666662974858819435n,
      ],
    });
    await circuit.checkConstraints(witness);
  });

  it("encode -1", async () => {
    const witness = await circuit.calculateWitness({ in: -1 }, true);
    const result = [
      1551705331698544401524786606720811740181943945870244569202198367044300364404n,
      20918696086212258109716309157665435087956178115434976279417465423469312201822n,
    ];
    await circuit.assertOut(witness, {
      out: result,
    });
    await circuit.checkConstraints(witness);
  });

  it("encode 0x42", async () => {
    const witness = await circuit.calculateWitness({ in: 0x42 }, true);
    const result = [
      5520721918672064917347280398526519562725607465061028485851804404263332149374n,
      15552952328295689847327188987393079505308628175404295821602016444687698081549n,
    ];
    await circuit.assertOut(witness, {
      out: result,
    });
    await circuit.checkConstraints(witness);
  });
});
