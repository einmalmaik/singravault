const REQUIRED_ENV = [
  "VITE_SUPABASE_PROJECT_ID",
  "VITE_SUPABASE_PUBLISHABLE_KEY",
  "VITE_SUPABASE_URL",
  "VITE_SITE_URL",
  "VITE_OPAQUE_SERVER_STATIC_PUBLIC_KEY",
];

const missing = REQUIRED_ENV.filter((name) => !String(process.env[name] ?? "").trim());

if (missing.length > 0) {
  console.error(
    [
      "Official desktop release configuration is incomplete.",
      `Missing variables: ${missing.join(", ")}`,
      "Set the OFFICIAL_VITE_* repository variables and VITE_OPAQUE_SERVER_STATIC_PUBLIC_KEY repository secret before creating a release tag.",
    ].join("\n"),
  );
  process.exit(1);
}

for (const envName of ["VITE_SUPABASE_URL", "VITE_SITE_URL"]) {
  try {
    const value = String(process.env[envName]).trim();
    const url = new URL(value);

    if (!/^https?:$/.test(url.protocol)) {
      throw new Error("unsupported protocol");
    }
  } catch (error) {
    console.error(`Invalid URL in ${envName}: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}

console.log("Official desktop release configuration is complete.");
