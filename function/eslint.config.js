import js from '@eslint/js';
import importPlugin from 'eslint-plugin-import';
import prettier from 'eslint-config-prettier';
import globals from 'globals';

export default [
  js.configs.recommended,
  prettier,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.node,
      },
    },
    plugins: {
      import: importPlugin,
    },
    rules: {
      'import/prefer-default-export': 'off',
      'no-console': 'off',
      'no-restricted-syntax': 'off',
      'no-await-in-loop': 'off',
      'no-constant-condition': 'off',
      // AWS SDK v3 is provided by Lambda runtime, not bundled
      'import/no-unresolved': ['error', { ignore: ['^@aws-sdk/'] }],
      // Allow devDependencies in config files
      'import/no-extraneous-dependencies': ['error', { devDependencies: ['**/*.config.js', '**/*.config.mjs'] }],
    },
  },
];
