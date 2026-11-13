/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dp: {
          950: '#07050f',
          900: '#0d0b1a',
          800: '#120f22',
          700: '#1a1630',
          600: '#231e40',
          500: '#2d2855',
        },
        purple: {
          brand: '#7c3aed',
          light: '#9333ea',
          soft: '#a855f7',
          glow: 'rgba(124,58,237,0.25)',
        },
        severity: {
          red: '#FF4D4D',
          green: '#7CFF9A',
          orange: '#F97316',
        },
        accent: {
          DEFAULT: '#22d3ee',
          light: '#67e8f9',
          dark: '#0891b2',
        }
      },
      fontFamily: {
        display: ['Space Grotesk', 'sans-serif'],
        body: ['Inter', 'sans-serif'],
        mono: ['Fira Code', 'monospace'],
      },
      boxShadow: {
        'purple-glow': '0 0 20px rgba(124,58,237,0.3)',
        'purple-sm': '0 0 8px rgba(124,58,237,0.2)',
      },
      backgroundImage: {
        'sidebar-active': 'linear-gradient(135deg, #7c3aed 0%, #9333ea 100%)',
        'run-btn': 'linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%)',
      }
    },
  },
  plugins: [],
}
