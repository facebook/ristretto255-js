/* Set-up */
const t00 = performance.now();
const NUM_OF_REPS = 100;
const ristretto_EC_points = [];
const ristretto_serialized_points = [];
const hashes = [];
const scalars = [];
const h = [ristretto.nacl_gf(), ristretto.nacl_gf(), ristretto.nacl_gf(), ristretto.nacl_gf()];
/* Generate random ristretto points */
for (let i = 0; i < NUM_OF_REPS; i++) {
    const ristretto_EC_point = ristretto.ristretto255_random();
    ristretto_EC_points.push(ristretto_EC_point);
    ristretto_serialized_points.push(ristretto.ristretto255_tobytes(ristretto_EC_point));
    hashes.push(new Uint8Array(crypto.subtle.digest("SHA-512", new TextEncoder("utf-8").encode(i + ""))));
    scalars.push(ristretto.crypto_core_ristretto255_scalar_random());
}

const functions = [
    {
        name: "Low-level ristretto functions",
        functions: [
            {
                name: "ristretto255_random",
                description: "Generates a random EC-ristretto point by calling from_hash on 64-elements random byte array",
                execute: () => ristretto.ristretto255_random(),
            },
            {
                name: "ristretto255_tobytes",
                description: "Serializes an EC-ristretto point to byte array",
                execute: () => ristretto.ristretto255_tobytes(ristretto_EC_points[i]),
            },
            {
                name: "ristretto255_frombytes",
                description: "Deserializes a byte array to an EC-ristretto point",
                execute: () => ristretto.ristretto255_tobytes(ristretto_EC_points[i]),
            },
            {
                name: "ristretto255_from_hash",
                description: "Generates an EC-ristretto point from a 64 elements byte array such as an output of SHA512",
                execute: () => ristretto.ristretto255_frombytes(h, ristretto_serialized_points[i]),
            }
        ],
    },
    {
        name: "High-level ristretto functions",
        functions: [
            {
                name: "crypto_core_ristretto255_random",
                description: "Generates a random EC-ristretto point and outputs a serialized byte array",
                execute: () => ristretto.crypto_core_ristretto255_random(),
            },
            {
                name: "crypto_core_ristretto255_from_hash",
                description: "Generates an EC-ristretto point from hash and outputs a serialized byte array",
                execute: () => ristretto.crypto_core_ristretto255_from_hash(hashes[i]),
            },
            {
                name: "crypto_core_ristretto255_add",
                description: "Deserializes input byte arrays to EC-ristretto points, adds them up and outputs a serialized result",
                execute: () => ristretto.crypto_core_ristretto255_add(ristretto_serialized_points[i], ristretto_serialized_points[(i + 1) % NUM_OF_REPS]),
            },
            {
                name: "crypto_core_ristretto255_sub",
                description: "Deserializes input byte arrays to EC-ristretto points, subtracts them up and outputs a serialized result",
                execute: () => ristretto.crypto_core_ristretto255_sub(ristretto_serialized_points[i], ristretto_serialized_points[(i + 1) % NUM_OF_REPS]),
            },
            {
                name: "crypto_scalarmult_ristretto255_base",
                description: "Multiplies a base EC-ristretto point by a scalar and outputs a serialized result",
                execute: () => ristretto.crypto_scalarmult_ristretto255_base(scalars[i]),
            },
            {
                name: "crypto_scalarmult_ristretto255",
                description: "Deserializes the input byte array to an EC-ristretto point, multiplies by a scalar and outputs a serialized result",
                execute: () => ristretto.crypto_scalarmult_ristretto255(scalars[i], ristretto_serialized_points[i]),
            },
        ],
    },
    {
        name: "High-level EC-ristretto functions",
        functions: [
            {
                name: "nacl_add",
                description: "Add two EC-ristretto points, outputs a resulting EC-ristretto point",
                execute: () => ristretto.nacl_add(ristretto_EC_points[i], ristretto_EC_points[i % NUM_OF_REPS]),
            },
            {
                name: "sub",
                description: "Subtract two EC-ristretto points, outputs a resulting EC-ristretto point",
                execute: () => ristretto.sub(ristretto_EC_points[i], ristretto_EC_points[i % NUM_OF_REPS]),
            },
            {
                name: "nacl_scalarbase",
                description: "Multiply a base EC-ristretto point by a scalar, outputs a resulting EC-ristretto point",
                execute: () => ristretto.nacl_scalarbase(ristretto_EC_points[i], scalars[i]),
            },
            {
                name: "nacl_scalarmult",
                description: "Multiply an EC-ristretto point by a scalar, outputs a resulting EC-ristretto point",
                execute: () => ristretto.nacl_scalarmult(ristretto_EC_points[i], ristretto_EC_points[i % NUM_OF_REPS], scalars[i]),
            },
        ],
    },
    {
        name: "Scalar operations",
        functions: [
            {
                name: "crypto_core_ristretto255_scalar_random",
                description: "Generates a random scalar",
                execute: () => ristretto.crypto_core_ristretto255_scalar_random(),
            },
            {
                name: "crypto_core_ristretto255_scalar_invert",
                description: "Inverts a scalar",
                execute: () => ristretto.crypto_core_ristretto255_scalar_invert(scalars[i]),
            },
            {
                name: "crypto_core_ristretto255_scalar_negate",
                description: "Negates a scalar",
                execute: () => ristretto.crypto_core_ristretto255_scalar_negate(scalars[i], scalars[i % NUM_OF_REPS]),
            },
            {
                name: "crypto_core_ristretto255_scalar_add",
                description: "Adds two scalars",
                execute: () => ristretto.crypto_core_ristretto255_scalar_add(scalars[i], scalars[i % NUM_OF_REPS]),
            },
            {
                name: "crypto_core_ristretto255_scalar_sub",
                description: "Subtracts two scalars",
                execute: () => ristretto.crypto_core_ristretto255_scalar_sub(scalars[i], scalars[i % NUM_OF_REPS]),
            },
            {
                name: "crypto_core_ristretto255_scalar_mul",
                description: "Multiplies two scalars",
                execute: () => ristretto.crypto_core_ristretto255_scalar_mul(scalars[i], scalars[i % NUM_OF_REPS]),
            },
        ],
    },
];

const template = (groupName, results) => `
<h2>${groupName}</h2>
<div class="benchmarks">
    <table class="benchmarks">
        <tr>
            <th>Function name</th>
            <th>Time in ms</th>
            <th>Comments</th>
        </tr>
        ${results.map(result => {
            return `
                <tr>
                    <td>${result.functionName}</td>
                    <td>${result.timing}</td>
                    <td>${result.description}</td>
                </tr>
            `;
        }).join('')}
    </table>
</div>`;

const generateBenchmarks = () => {

    functions.forEach(group => {
        const results = group.functions.map(func => {
            const t0 = performance.now();
            for (i = 0; i < NUM_OF_REPS; i++) {
                func.execute();
            }
            const t1 = performance.now();
            return {
                functionName: func.name,
                description: func.description,
                timing: ((t1 - t0) / NUM_OF_REPS).toFixed(3)
            }
        });
        document.getElementById('container').innerHTML += template(group.name, results);
    });
};

generateBenchmarks();

var t01 = performance.now();
document.getElementById("total_time").innerHTML = "Benchmark runtime: " + ((t01 - t00) / 1000).toFixed(2) + " sec with " + NUM_OF_REPS + " reps on each operation.";
