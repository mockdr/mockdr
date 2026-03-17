/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js,ts}'],
  theme: {
    extend: {
      colors: {
        s1: {
          sidebar: '#0A0E1A',
          bg:      '#0F1320',
          card:    '#161B2E',
          border:  '#1E2640',
          hover:   '#1A2035',
          primary: '#6E45E2',
          'primary-dark': '#5533BB',
          cyan:    '#00C2FF',
          danger:  '#FF4B4B',
          warning: '#FFB547',
          success: '#00D8A0',
          accent:  '#6E45E2',
          input:   '#0F1320',
          text:    '#E2E8F0',
          muted:   '#64748B',
          subtle:  '#94A3B8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
