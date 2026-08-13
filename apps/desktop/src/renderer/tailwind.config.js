/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        surface: "var(--surface)",
        "surface-variant": "var(--surface-variant)",
        primary: {
          DEFAULT: "var(--primary)",
          glow: "rgba(var(--primary-rgb), 0.4)",
        },
        secondary: {
          DEFAULT: "#22d3ee",
          glow: "rgba(34, 211, 238, 0.3)",
        },
        text: {
          primary: "var(--text-primary)",
          secondary: "var(--text-secondary)",
          muted: "var(--text-muted)",
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      borderRadius: {
        '3xl': '24px',
        '4xl': '32px',
      },
      backgroundImage: {
        'accent-gradient': "linear-gradient(135deg, #6366f1, #a855f7)",
        'success-gradient': "linear-gradient(135deg, #10b981, #059669)",
        'danger-gradient': "linear-gradient(135deg, #ef4444, #dc2626)",
      }
    },
  },
  plugins: [],
}
