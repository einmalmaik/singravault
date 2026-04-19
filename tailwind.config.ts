import type { Config } from "tailwindcss";
import tailwindcssAnimate from "tailwindcss-animate";

export default {
  darkMode: ["class"],
  content: [
    "./index.html",
    "./pages/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./app/**/*.{ts,tsx}",
    "./src/**/*.{ts,tsx}",
    "../singra-premium/src/**/*.{ts,tsx}",
    "../singra-premium/dist/**/*.{js,mjs}",
    "./node_modules/@singra/premium/dist/**/*.{js,mjs}",
  ],
  prefix: "",
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        success: {
          DEFAULT: "hsl(var(--success))",
          foreground: "hsl(var(--success-foreground))",
        },
        warning: {
          DEFAULT: "hsl(var(--warning))",
          foreground: "hsl(var(--warning-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        sidebar: {
          DEFAULT: "hsl(var(--sidebar-background))",
          foreground: "hsl(var(--sidebar-foreground))",
          primary: "hsl(var(--sidebar-primary))",
          "primary-foreground": "hsl(var(--sidebar-primary-foreground))",
          accent: "hsl(var(--sidebar-accent))",
          "accent-foreground": "hsl(var(--sidebar-accent-foreground))",
          border: "hsl(var(--sidebar-border))",
          ring: "hsl(var(--sidebar-ring))",
        },
        glow: {
          primary: "hsl(var(--glow-primary))",
          secondary: "hsl(var(--glow-secondary))",
          strong: "hsl(var(--glow-strong))",
        },
        // Elevation layers - consistent surface depth system
        el: {
          0: "hsl(var(--el-0))",
          1: "hsl(var(--el-1))",
          2: "hsl(var(--el-2))",
          3: "hsl(var(--el-3))",
          4: "hsl(var(--el-4))",
          5: "hsl(var(--el-5))",
        },
        // Password Manager Mode Accent Colors
        mode: {
          // Password strength modes
          weak: "hsl(var(--mode-weak))",
          "weak-muted": "hsl(var(--mode-weak-muted))",
          fair: "hsl(var(--mode-fair))",
          "fair-muted": "hsl(var(--mode-fair-muted))",
          strong: "hsl(var(--mode-strong))",
          "strong-muted": "hsl(var(--mode-strong-muted))",
          // Feature modes
          generator: "hsl(var(--mode-generator))",
          "generator-muted": "hsl(var(--mode-generator-muted))",
          vault: "hsl(var(--mode-vault))",
          "vault-muted": "hsl(var(--mode-vault-muted))",
        },
        zingra: {
          blue: "hsl(var(--zingra-blue))",
          "blue-dark": "hsl(var(--zingra-blue-dark))",
          "blue-light": "hsl(var(--zingra-blue-light))",
        },
      },
      backgroundImage: {
        'gradient-singularity': 'var(--gradient-singularity)',
        'gradient-orbit': 'var(--gradient-orbit)',
        'gradient-vault': 'var(--gradient-vault)',
        'gradient-password': 'var(--gradient-password)',
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        gradient: {
          "0%, 100%": {
            "background-size": "200% 200%",
            "background-position": "left center",
          },
          "50%": {
            "background-size": "200% 200%",
            "background-position": "right center",
          },
        },
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        shimmer: {
          "0%": { "background-position": "-200% center" },
          "100%": { "background-position": "200% center" },
        },
        "slide-up": {
          from: { opacity: "0", transform: "translateY(10px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "slide-in-right": {
          from: { opacity: "0", transform: "translateX(20px)" },
          to: { opacity: "1", transform: "translateX(0)" },
        },
        "typing-dot": {
          "0%, 60%, 100%": { transform: "translateY(0)", opacity: "0.35" },
          "30%": { transform: "translateY(-5px)", opacity: "1" },
        },
        "strength-pulse": {
          "0%, 100%": { transform: "scale(1)", opacity: "1" },
          "50%": { transform: "scale(1.05)", opacity: "0.8" },
        },
        "vault-unlock": {
          "0%": { transform: "rotate(0deg) scale(1)" },
          "25%": { transform: "rotate(-5deg) scale(1.02)" },
          "50%": { transform: "rotate(0deg) scale(1)" },
          "75%": { transform: "rotate(5deg) scale(1.02)" },
          "100%": { transform: "rotate(0deg) scale(1)" },
        },
        "fade-in-scale": {
          from: { opacity: "0", transform: "scale(0.975)" },
          to: { opacity: "1", transform: "scale(1)" },
        },
        "scan-line": {
          "0%": { transform: "translateY(-100%)", opacity: "0" },
          "20%": { opacity: "0.6" },
          "80%": { opacity: "0.6" },
          "100%": { transform: "translateY(400%)", opacity: "0" },
        },
        "auth-float": {
          "0%, 100%": { transform: "translateY(0) translateX(0)" },
          "25%": { transform: "translateY(-20px) translateX(10px)" },
          "50%": { transform: "translateY(-10px) translateX(-5px)" },
          "75%": { transform: "translateY(-25px) translateX(8px)" },
        },
        "auth-glow-pulse": {
          "0%, 100%": { opacity: "0.3", transform: "scale(1)" },
          "50%": { opacity: "0.6", transform: "scale(1.15)" },
        },
        "auth-slide-in": {
          "0%": { opacity: "0", transform: "translateX(24px)" },
          "100%": { opacity: "1", transform: "translateX(0)" },
        },
        "auth-slide-out": {
          "0%": { opacity: "1", transform: "translateX(0)" },
          "100%": { opacity: "0", transform: "translateX(-24px)" },
        },
        "auth-brand-reveal": {
          "0%": { opacity: "0", transform: "translateX(-40px)" },
          "100%": { opacity: "1", transform: "translateX(0)" },
        },
        "auth-form-reveal": {
          "0%": { opacity: "0", transform: "translateY(20px) scale(0.98)" },
          "100%": { opacity: "1", transform: "translateY(0) scale(1)" },
        },
        "auth-field-in": {
          "0%": { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "auth-ring-spin": {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        "vault-shimmer": {
          "0%": { backgroundPosition: "-200% center" },
          "100%": { backgroundPosition: "200% center" },
        },
        "password-reveal": {
          "0%": { filter: "blur(4px)", opacity: "0" },
          "100%": { filter: "blur(0)", opacity: "1" },
        },
        "key-rotate": {
          "0%": { transform: "rotate(-15deg)" },
          "50%": { transform: "rotate(15deg)" },
          "100%": { transform: "rotate(0deg)" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "spin-slow": "spin 30s linear infinite",
        "gradient": "gradient 8s ease infinite",
        "fade-in": "fadeIn 0.3s ease-out",
        "shimmer": "shimmer 1.8s linear infinite",
        "slide-up": "slide-up 0.28s cubic-bezier(0.34, 1.56, 0.64, 1) forwards",
        "slide-in-right": "slide-in-right 0.3s ease-out",
        "typing-dot": "typing-dot 1.4s ease-in-out infinite",
        "strength-pulse": "strength-pulse 1.8s ease-in-out infinite",
        "vault-unlock": "vault-unlock 0.6s ease-in-out",
        "fade-in-scale": "fade-in-scale 0.2s ease-out forwards",
        "scan-line": "scan-line 2.4s ease-in-out infinite",
        "auth-float": "auth-float 6s ease-in-out infinite",
        "auth-glow-pulse": "auth-glow-pulse 4s ease-in-out infinite",
        "auth-slide-in": "auth-slide-in 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards",
        "auth-slide-out": "auth-slide-out 0.25s ease-in forwards",
        "auth-brand-reveal": "auth-brand-reveal 0.7s cubic-bezier(0.16, 1, 0.3, 1) forwards",
        "auth-form-reveal": "auth-form-reveal 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards",
        "auth-field-in": "auth-field-in 0.35s ease-out forwards",
        "auth-ring-spin": "auth-ring-spin 20s linear infinite",
        "vault-shimmer": "vault-shimmer 2s linear infinite",
        "password-reveal": "password-reveal 0.3s ease-out forwards",
        "key-rotate": "key-rotate 0.4s ease-in-out",
        pulse: "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
    },
  },
  plugins: [tailwindcssAnimate],
} satisfies Config;
