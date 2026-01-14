/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './index.php',
    './register.php',
    './views/**/*.php',
  ],
  theme: {
    extend: {
      colors: {
        primary: '#134658',
        'background-light': '#f6f7f8',
        'background-dark': '#121c20',
        'vault-dark': '#1e293b',
        'vault-border': '#334155',
        'surface-dark': '#1a2428',
        'border-dark': '#2a3337',
        'accent-green': '#5F9E6C',
        'accent-red': '#ae4d4d',
      },
      fontFamily: {
        display: ['Manrope', 'sans-serif'],
      },
      borderRadius: {
        DEFAULT: '0.25rem',
        lg: '0.5rem',
        xl: '0.75rem',
        '2xl': '1rem',
        full: '9999px',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/container-queries'),
  ],
};
