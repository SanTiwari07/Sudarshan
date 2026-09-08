/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        surface: {
          page: 'var(--surface-page)',
          card: 'var(--surface-card)',
          secondary: 'var(--surface-secondary)',
          active: 'var(--surface-active)',
          hover: 'var(--surface-hover)',
          input: 'var(--surface-input)',
        }
      },
      // Base scale bumped one step up across the board. The console is read on
      // projectors and shared screens, not just at a desk, and the previous
      // 12/14/16 rhythm was too tight for that. Everything here is +1 to +2px.
      fontSize: {
        xs: ['0.8125rem', { lineHeight: '1.125rem' }],   // 13px
        sm: ['0.9375rem', { lineHeight: '1.375rem' }],   // 15px
        base: ['1.0625rem', { lineHeight: '1.625rem' }], // 17px
        lg: ['1.1875rem', { lineHeight: '1.8125rem' }],  // 19px
        xl: ['1.3125rem', { lineHeight: '1.875rem' }],   // 21px
        '2xl': ['1.5625rem', { lineHeight: '2.125rem' }],// 25px
        '3xl': ['1.9375rem', { lineHeight: '2.375rem' }],// 31px
        '4xl': ['2.375rem', { lineHeight: '2.625rem' }], // 38px
        '5xl': ['3.125rem', { lineHeight: '1' }],        // 50px
        '6xl': ['3.875rem', { lineHeight: '1' }],        // 62px
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        // Retained as an alias of the body face. Headings used to be set in
        // Inter Tight, but a narrower face at 18px beside 15px body reads as a
        // second font rather than as hierarchy - which is what it looked like.
        // Hierarchy comes from weight, size and colour instead.
        display: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
