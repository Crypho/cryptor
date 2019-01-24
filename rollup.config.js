import typescript from 'rollup-plugin-typescript2';
import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import pkg from './package.json';

const defaultOptions = (tsConfig={}) => ({
  plugins: [
    resolve(),
    commonjs({
      namedExports: {
        'node_modules/chai/index.js': ['expect'],
      },
    }),
    typescript({tsconfigOverride: 'tsConfig'}),
  ]
})


export default [
  // Browser-friendly UMD build
  {
    input: 'src/index.ts',
    output: {
      format: 'umd',
      name: "cryptor",
      file: pkg.browser,
    },
    ...defaultOptions(),
  },

  // CommonJS and ES module for bundlers
  {
    input: 'src/index.ts',
    output: [
      {
        file: pkg.main,
        format: "cjs",
      },
      { file: pkg.module, format: 'es'},
    ],
    ...defaultOptions(),
  },

  // Tests output
  {
    input: 'test/index.ts',
    output: {
      name: 'cryptorTest',
      file: 'test/index.js',
      format: 'iife',
      sourcemap: true
    },
    ...defaultOptions({
      compilerOptions: {
        target: 'ES2016',
        sourceMap: true,
      },
    }),
  },
]
