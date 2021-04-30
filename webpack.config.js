/* eslint-disable import/no-extraneous-dependencies */
const slsw = require('serverless-webpack');
// const webpack = require('webpack');
const nodeExternals = require('webpack-node-externals');

/*
const definePluginConfig = new webpack.DefinePlugin({
  'process.env': {
    REGION: JSON.stringify(infra.region),
  },
});
*/

module.exports = {
  entry: slsw.lib.entries,
  target: 'node',
  mode: 'production',
  externals: nodeExternals(),

  module: {
    rules: [
      {
        test: /\.(js)$/,
        exclude: /node_modules/,
        use: ['babel-loader'],
      },
    ],
  },
  // plugins: [definePluginConfig],
  resolve: {
    extensions: ['.js'],
  },
};
