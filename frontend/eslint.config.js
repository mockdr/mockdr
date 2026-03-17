import pluginVue from 'eslint-plugin-vue'
import { defineConfigWithVueTs, vueTsConfigs } from '@vue/eslint-config-typescript'

export default defineConfigWithVueTs(
  { ignores: ['dist/**', 'coverage/**', 'node_modules/**'] },
  pluginVue.configs['flat/recommended'],
  vueTsConfigs.recommended,
  {
    rules: {
      // No any casts in production code (TESTING.md §4.3)
      '@typescript-eslint/no-explicit-any': 'error',
      // Vue-specific logic rules
      'vue/multi-word-component-names': 'off',
      'vue/require-default-prop': 'off',
      // HTML formatting — delegated to editor/Prettier, not ESLint's responsibility
      'vue/max-attributes-per-line': 'off',
      'vue/html-indent': 'off',
      'vue/first-attribute-linebreak': 'off',
      'vue/html-closing-bracket-newline': 'off',
      'vue/singleline-html-element-content-newline': 'off',
      'vue/html-self-closing': 'off',
      'vue/attributes-order': 'off',
      'vue/multiline-html-element-content-newline': 'off',
      'vue/html-quotes': 'off',
    },
  },
)
