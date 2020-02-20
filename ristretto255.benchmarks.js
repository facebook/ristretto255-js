/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/* global ristretto255 */

/* Set-up */
const t00 = performance.now();
const NUM_OF_REPS = 100;
const ristrettoECPoints = [];
const ristrettoSerializedPoints = [];
const hashes = [];
const scalars = [];
const h = ristretto255.unsafe.point.alloc();
/* Generate random ristretto points */
for (let i = 0; i < NUM_OF_REPS; i++) {
  const ristrettoECPoint = ristretto255.unsafe.point.getRandom();
  ristrettoECPoints.push(ristrettoECPoint);
  ristrettoSerializedPoints.push(
    ristretto255.unsafe.point.toBytes(ristrettoECPoint)
  );
  hashes.push(
    new Uint8Array(
      crypto.subtle.digest('SHA-512', new TextEncoder('utf-8').encode(`${i}`))
    )
  );
  scalars.push(ristretto255.scalar.getRandom());
}

const functions = [
  {
    // ristretto points are represented as Uint8Array(32)
    name: 'High-level ristretto255 group operations',
    functions: [
      {
        name: 'getRandom',
        description: 'Generate a random group element',
        execute: () => ristretto255.getRandom()
      },
      {
        name: 'isValid',
        description: 'Check if a value represents a valid element',
        execute: i => ristretto255.isValid(ristrettoSerializedPoints[i])
      },
      {
        name: 'fromHash',
        description:
          'Hash to group: generate a group element from 64-element byte array, e.g. an output of SHA-512',
        execute: i => ristretto255.fromHash(hashes[i])
      },
      {
        name: 'add',
        description: 'Add two group elements',
        execute: i =>
          ristretto255.add(
            ristrettoSerializedPoints[i],
            ristrettoSerializedPoints[(i + 1) % NUM_OF_REPS]
          )
      },
      {
        name: 'sub',
        description: 'Subtract two group elements',
        execute: i =>
          ristretto255.sub(
            ristrettoSerializedPoints[i],
            ristrettoSerializedPoints[(i + 1) % NUM_OF_REPS]
          )
      },
      {
        name: 'scalarMultBase',
        description: 'Multiply a generator of the group by a scalar',
        execute: i => ristretto255.scalarMultBase(scalars[i])
      },
      {
        name: 'scalarMult',
        description: 'Multiply a group element by a scalar',
        execute: i =>
          ristretto255.scalarMult(scalars[i], ristrettoSerializedPoints[i])
      }
    ]
  },
  {
    name: 'Scalar operations',
    functions: [
      {
        name: 'scalar.getRandom',
        description: 'Generate a random scalar',
        execute: () => ristretto255.scalar.getRandom()
      },
      {
        name: 'scalar.invert',
        description: 'Invert a scalar',
        execute: i => ristretto255.scalar.invert(scalars[i])
      },
      {
        name: 'scalar.negate',
        description: 'Negate a scalar',
        execute: i =>
          ristretto255.scalar.negate(scalars[i], scalars[i % NUM_OF_REPS])
      },
      {
        name: 'scalar.add',
        description: 'Add two scalars',
        execute: i =>
          ristretto255.scalar.add(scalars[i], scalars[i % NUM_OF_REPS])
      },
      {
        name: 'scalar.sub',
        description: 'Subtract two scalars',
        execute: i =>
          ristretto255.scalar.sub(scalars[i], scalars[i % NUM_OF_REPS])
      },
      {
        name: 'scalar.mul',
        description: 'Multiply two scalars',
        execute: i =>
          ristretto255.scalar.mul(scalars[i], scalars[i % NUM_OF_REPS])
      }
    ]
  },
  {
    name: 'Low-level unsafe functions (unless if used by a cryptographer)',
    functions: [
      {
        name: 'unsafe.point.toBytes',
        description:
          'Serialize a curve25519 point to ristretto255 group element',
        execute: i => ristretto255.unsafe.point.toBytes(ristrettoECPoints[i])
      },
      {
        name: 'unsafe.point.fromBytes',
        description:
          'Deserialize a curve25519 point from ristretto255 group element',
        execute: i =>
          ristretto255.unsafe.point.fromBytes(h, ristrettoSerializedPoints[i])
      },
      {
        name: 'unsafe.point.getRandom',
        description:
          'Generate a random ristretto255 group element represented as curve25519 point',
        execute: () => ristretto255.unsafe.point.getRandom()
      },
      {
        name: 'unsafe.point.fromHash',
        description:
          'Generate a ristretto255 group element represented as curve25519 point from a 64 elements byte array such as an output of SHA512',
        execute: i => ristretto255.unsafe.point.fromHash(hashes[i])
      },
      {
        name: 'unsafe.point.add',
        description: 'Add two curve25519 points',
        execute: i =>
          ristretto255.unsafe.point.add(
            ristrettoECPoints[i],
            ristrettoECPoints[i % NUM_OF_REPS]
          )
      },
      {
        name: 'unsafe.point.sub',
        description: 'Subtract two curve25519 points',
        execute: i =>
          ristretto255.unsafe.point.sub(
            ristrettoECPoints[i],
            ristrettoECPoints[i % NUM_OF_REPS]
          )
      },
      {
        name: 'unsafe.point.scalarMultBase',
        description: "Multiply a curve25519's base point by a scalar",
        execute: i =>
          ristretto255.unsafe.point.scalarMultBase(
            ristrettoECPoints[i],
            scalars[i]
          )
      },
      {
        name: 'unsafe.point.scalarMult',
        description: "Multiply a curve25519's point by a scalar",
        execute: i =>
          ristretto255.unsafe.point.scalarMult(
            ristrettoECPoints[i],
            ristrettoECPoints[i % NUM_OF_REPS],
            scalars[i]
          )
      }
    ]
  }
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
        ${results
          .map(result => {
            return `
                <tr>
                    <td>${result.functionName}</td>
                    <td>${result.timing}</td>
                    <td>${result.description}</td>
                </tr>
            `;
          })
          .join('')}
    </table>
</div>`;

function average(data) {
  const sum = data.reduce(function add(acc, value) {
    return acc + value;
  }, 0);

  const avg = sum / data.length;
  return avg;
}

// The credit for computing std goes to
// https://derickbailey.com/2014/09/21/calculating-standard-deviation-with-array-map-and-array-reduce-in-javascript/
function standardDeviation(values) {
  const avg = average(values);

  const squareDiffs = values.map(function f(value) {
    const diff = value - avg;
    const sqrDiff = diff * diff;
    return sqrDiff;
  });

  const stdDev = Math.sqrt(average(squareDiffs));
  return stdDev;
}

const generateBenchmarks = () => {
  functions.forEach(group => {
    const results = group.functions.map(func => {
      // const t0 = performance.now();
      const timing = [];
      for (let i = 0; i < NUM_OF_REPS; i++) {
        const t0 = performance.now();
        func.execute(i);
        const t1 = performance.now();
        timing.push(t1 - t0);
      }
      // compute the average
      const avg = average(timing);
      const std = standardDeviation(timing);

      return {
        functionName: func.name,
        description: func.description,
        timing: `${avg.toFixed(
          2
        )}<small font-size="smaller"> &#177; ${std.toFixed(2)}</small>`
      };
    });
    document.getElementById('container').innerHTML += template(
      group.name,
      results
    );
  });
};

generateBenchmarks();

const t01 = performance.now();
document.getElementById('total_time').innerHTML = `Benchmark runtime: ${(
  (t01 - t00) /
  1000
).toFixed(2)} sec with ${NUM_OF_REPS} reps on each operation.`;
