import globals from 'globals';
import pluginJs from '@eslint/js';
import pluginHtml from 'eslint-plugin-html';

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
      quotes: ['error', 'single'],
      semi: ['error', 'always'],
    },
  },
  pluginJs.configs.recommended,
  {
    files: ['apps/*.html'],
    plugins: { pluginHtml }
  },
];
