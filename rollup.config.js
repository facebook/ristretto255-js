import { uglify } from 'rollup-plugin-uglify';
import babel from 'rollup-plugin-babel';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default {
    input: 'ristretto.js',
    output: {
        file: 'ristretto.min.js',
        format: 'umd',
        name: 'ristretto',
        globals: {
            crypto: 'crypto'
        }
    },
    external: [ 'crypto' ],
    plugins: [
        babel({
            exclude: 'node_modules/**'
        }),
        uglify(),
        resolve(),
        commonjs()
    ]
};
