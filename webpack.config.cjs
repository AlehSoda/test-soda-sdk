const path = require('path');

module.exports = {
  entry: './js/index.mjs', // The entry point of your ESM code
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'index.js',
    library: 'SodaJsSdk',
    libraryTarget: 'umd', // Output format that is compatible with both CommonJS and AMD
    globalObject: 'this', // Fixes issue with `window` and `global` in different environments
  },
  module: {
    rules: [
      {
        test: /\.m?js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env'],
          },
        },
      },
    ],
  },
  mode: 'production', // Use 'development' for easier debugging
};
