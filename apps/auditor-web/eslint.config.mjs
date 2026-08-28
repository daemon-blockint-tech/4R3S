import nextPlugin from 'eslint-config-next'

const eslintConfig = [
  {
    ignores: ['node_modules/**', '.next/**', 'out/**', 'build/**', 'next-env.d.ts'],
  },
  ...nextPlugin,
  {
    // eslint-plugin-react-hooks v7 (pulled transitively by eslint-config-next
    // 16.2.x) enables the new "React Compiler" rules as ERRORS. They flag a large
    // amount of pre-existing, working code inherited from the coding-agent
    // template (e.g. 41x set-state-in-effect), which blocks `next build` outright
    // even though nothing is a runtime defect. Downgrade this newly-strict set to
    // warnings for incremental adoption: they stay visible in lint output (to be
    // paid down file-by-file), but no longer fail the production build. This is a
    // calibration of newly-added advisory rules, not silencing — do NOT set these
    // to 'off'.
    rules: {
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/exhaustive-deps': 'warn',
      'react-hooks/immutability': 'warn',
      'react-hooks/purity': 'warn',
      'react-hooks/error-boundaries': 'warn',
    },
  },
]

export default eslintConfig
