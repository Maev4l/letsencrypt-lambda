module.exports = {
  extends: ['airbnb-base', 'prettier'],
  env: {
    node: true,
  },
  rules: {
    'class-methods-use-this': ['off'],
    'import/prefer-default-export': 'off',
    'no-await-in-loop': 'off',
    'no-constant-condition': 'off',
  },
};
