/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // A restrained security-operations palette: deep slate base, cyan/azure
        // accents, semantic severity colours. No garish gradients (spec §25).
        base: {
          900: '#070b14', 850: '#0a1120', 800: '#0d1524',
          700: '#131d30', 600: '#1b263f', 500: '#263450',
        },
        accent: { DEFAULT: '#38bdf8', soft: '#7dd3fc', deep: '#0ea5e9' },
        sev: {
          critical: '#f43f5e', high: '#fb923c', medium: '#facc15',
          low: '#38bdf8', info: '#94a3b8', ok: '#34d399',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"SF Mono"', 'Menlo', 'Consolas', 'monospace'],
      },
      boxShadow: {
        glass: '0 8px 32px rgba(0,0,0,0.37)',
        glow: '0 0 0 1px rgba(56,189,248,0.3), 0 0 20px rgba(56,189,248,0.15)',
      },
      keyframes: {
        'fade-in': { '0%': { opacity: '0', transform: 'translateY(4px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        'pulse-dot': { '0%,100%': { opacity: '1' }, '50%': { opacity: '0.3' } },
        'scan-sweep': { '0%': { transform: 'translateX(-100%)' }, '100%': { transform: 'translateX(100%)' } },
      },
      animation: {
        'fade-in': 'fade-in 0.3s ease-out',
        'pulse-dot': 'pulse-dot 1.4s ease-in-out infinite',
        'scan-sweep': 'scan-sweep 1.6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};
