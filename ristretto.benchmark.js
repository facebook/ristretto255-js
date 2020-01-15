/* Set-up */
const t00 = performance.now();
const NUM_OF_REPS = 100;
const ristretto_EC_points = [];
const ristretto_serialized_points = [];
const hashes = [];
const scalars = [];
const h = [ristretto.unsafe_gf(), ristretto.unsafe_gf(), ristretto.unsafe_gf(), ristretto.unsafe_gf()];
/* Generate random ristretto points */
for (let i = 0; i < NUM_OF_REPS; i++) {
    const ristretto_EC_point = ristretto.unsafe_point_random();
    ristretto_EC_points.push(ristretto_EC_point);
    ristretto_serialized_points.push(ristretto.unsafe_tobytes(ristretto_EC_point));
    hashes.push(new Uint8Array(crypto.subtle.digest("SHA-512", new TextEncoder("utf-8").encode(i + ""))));
    scalars.push(ristretto.scalar_random());
}

// TODO: add a color-range
// TODO: add a +- standard deviation for numbers
const functions = [
    {
	// ristretto points are represented as Uint8Array(32)
        name: "High-level ristretto functions giving a prime order group (ristretto255)",
        functions: [
            {
                name: "random",
                description: "Generate a random group element",
                execute: () => ristretto.random(),
            },
            {
                name: "from_hash",
                description: "Hash to group: generate a group element from 64-element byte array, e.g. an output of SHA-512",
                execute: () => ristretto.from_hash(hashes[i]),
            },
            {
                name: "add",
                description: "Add two group elements",
                execute: () => ristretto.add(ristretto_serialized_points[i], ristretto_serialized_points[(i + 1) % NUM_OF_REPS]),
            },
            {
                name: "sub",
                description: "Subtract two group elements",
                execute: () => ristretto.sub(ristretto_serialized_points[i], ristretto_serialized_points[(i + 1) % NUM_OF_REPS]),
            },
            {
                name: "scalarmult_base",
                description: "Multiply a generator of the group by a scalar",
                execute: () => ristretto.scalarmult_base(scalars[i]),
            },
            {
                name: "scalarmult",
                description: "Multiply a group element by a scalar",
                execute: () => ristretto.scalarmult(scalars[i], ristretto_serialized_points[i]),
            },
	    // TODO: add is_valid
        ],
    },
    {
	// TODO: check if scalars need to be reduced prior to being put on the wire
	// scalars are represented as Float64Array(16)
        name: "Scalar operations",
        functions: [
            {
                name: "scalar_random",
                description: "Generate a random scalar",
                execute: () => ristretto.scalar_random(),
            },
            {
                name: "scalar_invert",
                description: "Invert a scalar",
                execute: () => ristretto.scalar_invert(scalars[i]),
            },
            {
                name: "scalar_negate",
                description: "Negate a scalar",
                execute: () => ristretto.scalar_negate(scalars[i], scalars[i % NUM_OF_REPS]),
            },
            {
                name: "scalar_add",
                description: "Add two scalars",
                execute: () => ristretto.scalar_add(scalars[i], scalars[i % NUM_OF_REPS]),
            },
            {
                name: "scalar_sub",
                description: "Subtract two scalars",
                execute: () => ristretto.scalar_sub(scalars[i], scalars[i % NUM_OF_REPS]),
            },
            {
                name: "scalar_mul",
                description: "Multiply two scalars",
                execute: () => ristretto.scalar_mul(scalars[i], scalars[i % NUM_OF_REPS]),
            },
        ],
    },
    {
        name: "Low-level functions: unsafe (unless if used by a cryptographer)",
        functions: [
            {
                name: "unsafe_point_random",
                description: "Generate a random ristretto255 group element represented as curve25519 point",
                execute: () => ristretto.unsafe_point_random(),
            },
            {
                name: "unsafe_tobytes",
                description: "Serialize a curve25519 point to ristretto255 group element",
                execute: () => ristretto.unsafe_tobytes(ristretto_EC_points[i]),
            },
            {
                name: "unsafe_frombytes",
                description: "Deserialize a curve25519 point from ristretto255 group element",
                execute: () => ristretto.unsafe_frombytes(h, ristretto_serialized_points[i]),
            },
            {
                name: "unsafe_point_from_hash",
                description: "Generate a ristretto255 group element represented as curve25519 point from a 64 elements byte array such as an output of SHA512",
                execute: () => ristretto.unsafe_point_from_hash(hashes[i]),
            },
            {
                name: "unsafe_point_add",
                description: "Add two curve25519 points",
                execute: () => ristretto.unsafe_point_add(ristretto_EC_points[i], ristretto_EC_points[i % NUM_OF_REPS]),
            },
            {
                name: "unsafe_point_sub",
                description: "Subtract two curve25519 points",
                execute: () => ristretto.unsafe_point_sub(ristretto_EC_points[i], ristretto_EC_points[i % NUM_OF_REPS]),
            },
            {
                name: "unsafe_point_scalarmult_base",
                description: "Multiply a curve25519's base point by a scalar",
                execute: () => ristretto.unsafe_point_scalarmult_base(ristretto_EC_points[i], scalars[i]),
            },
            {
                name: "unsafe_point_scalarmult",
                description: "Multiply a curve25519's point by a scalar",
                execute: () => ristretto.unsafe_point_scalarmult(ristretto_EC_points[i], ristretto_EC_points[i % NUM_OF_REPS], scalars[i]),
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
