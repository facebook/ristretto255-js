/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { terser } from 'rollup-plugin-terser';
import babel from '@rollup/plugin-babel';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

const babelconfig = require('./babel.config');

export default [
  {
    input: 'src/ristretto255.js',
    output: {
      file: 'dist/ristretto255.min.js',
      format: 'umd',
      name: 'ristretto255'
    },
    plugins: [
      babel({
        exclude: 'node_modules/**',
        babelrc: false,
        babelHelpers: 'bundled',
        ...babelconfig
      }),
      terser(),
      resolve({
        browser: true
      }),
      commonjs()
    ]
  },
  {
    input: 'ristretto255.benchmarks.js',
    output: {
      file: 'ristretto255.benchmarks.min.js',
      format: 'umd',
      name: 'ristretto255_benchmarks'
    },
    plugins: [
      babel({
        exclude: 'node_modules/**',
        babelrc: false,
        babelHelpers: 'bundled',
        ...babelconfig
      }),
      terser(),
      resolve(),
      commonjs()
    ]
  }
];
