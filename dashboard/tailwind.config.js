/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        'ps-bg': '#060911',
        'ps-surface': '#0d1117',
        'ps-border': '#21262d',
        'ps-low': '#22c55e',
        'ps-medium': '#f59e0b',
        'ps-high': '#f97316',
        'ps-critical': '#ef4444',
        'ps-accent': '#58a6ff',
        'ps-purple': '#7c3aed',
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
};
