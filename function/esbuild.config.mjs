import esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['src/main.js'],
  bundle: true,
  minify: true,
  platform: 'node',
  target: 'node22',
  outdir: 'bin',
  format: 'cjs',
  // AWS SDK v3 is provided by Lambda runtime
  external: [
    '@aws-sdk/client-acm',
    '@aws-sdk/client-route-53',
    '@aws-sdk/client-s3',
    '@aws-sdk/client-sns',
  ],
});
