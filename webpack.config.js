// Instead of require, use import
import path from 'path';

// Webpack configuration using export default for ES modules
export default {
  entry: './js/index.js',  // Entry point of your SDK
  output: {
    filename: 'soda-js-sdk.umd.js',  // Output UMD bundle
    path: path.resolve('dist'),  // Output directory
    library: 'SodaJsSdk',  // Global variable name for browser
    libraryTarget: 'umd',  // Universal Module Definition (UMD) format
    globalObject: 'this'   // Fixes issues with 'window' in Node.js environments
  },
  mode: 'production',
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env']  // Transpile for older browsers
          }
        }
      }
    ]
  }
};
