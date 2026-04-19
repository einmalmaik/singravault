export const designTheme = {
  tokenSource: "src/design/tokens.css",
  themeColor: "#c7e5ed",
  backgroundColor: "#070b0d",
  foregroundColor: "#eff8f9",
} as const;

export const designTokenNames = [
  "background",
  "foreground",
  "card",
  "card-foreground",
  "popover",
  "popover-foreground",
  "primary",
  "primary-foreground",
  "secondary",
  "secondary-foreground",
  "muted",
  "muted-foreground",
  "accent",
  "accent-foreground",
  "destructive",
  "destructive-foreground",
  "success",
  "success-foreground",
  "warning",
  "warning-foreground",
  "border",
  "input",
  "ring",
  "radius",
] as const;

export type DesignTheme = typeof designTheme;
export type DesignTokenName = (typeof designTokenNames)[number];
