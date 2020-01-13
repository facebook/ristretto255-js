import { uglify } from 'rollup-plugin-uglify';
import babel from 'rollup-plugin-babel';

export default {
    input: 'ristretto.js',
    output: {
        file: 'ristretto.min.js',
        format: 'umd',
        name: 'ristretto'
    },
    external: [ 'crypto' ],
    plugins: [
        babel({
            exclude: 'node_modules/**'
        }),
        uglify()
    ]
};
