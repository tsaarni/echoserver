import globals from 'globals';
import pluginJs from '@eslint/js';

/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      eqeqeq: 'error',
      curly: 'error',
      'no-unused-vars': 'error',
      'no-console': 'warn',
      strict: ['error', 'global'],
    },
  },
  pluginJs.configs.recommended,
];
