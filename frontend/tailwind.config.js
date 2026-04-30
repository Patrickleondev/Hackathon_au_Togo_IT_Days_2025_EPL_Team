/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eef2ff', 100: '#e0e7ff',
          200: '#c7d2fe', 300: '#a5b4fc', 400: '#818cf8',
          500: '#4f46e5',
          600: '#4338ca', 700: '#3730a3', 900: '#312e81',
        },
        danger: { 500: '#ef4444', 600: '#dc2626' },
        warn:   { 500: '#f59e0b' },
        ok:     { 500: '#10b981' },
      }
    },
  },
  plugins: [],
}
