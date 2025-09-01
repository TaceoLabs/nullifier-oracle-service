const { wasm } = require("circom_tester");
const { expect } = require("chai");
const path = require("path");

describe("EdDSA Poseidon2", function () {
  this.timeout(10000);

  let circuit;
  before(async () => {
    circuit = await wasm(
      path.join(__dirname, "circuits/eddsaposeidon2_test.circom"),
      { include: [path.join(__dirname, "../../")] },
    );
    await circuit.loadConstraints();
  });


  it("kat0 success", async () => {
    const witness = await circuit.calculateWitness({enabled: 1, Ax: 16678259879098414123498807254435611303785911063700858304367872369684614918416, Ay: 7888819232908132535915269475302946450083176441390977566673707888303107893510, S: 1573999702038249631679919850435194863813136906634296727651724032347031741575, R8x: 9324174297151491549264811692384430723560494801467612063988128019217786550764, R8y: 15483619585430622646805622121878925743133950545354786707241324402663412566491, M: 3126080974277891902445700130528654565374341115115698716199527644337840721369 }, true);
    await circuit.checkConstraints(witness);
  });
});

// TODO add second kat1
// TODO add s + p
// TODO add kat0 with bitflip
