import { existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { resolve } from "node:path";

const pat = process.env.GITHUB_PAT;
const installPremiumFlag = process.env.INSTALL_SINGRA_PREMIUM;
const premiumRef = process.env.SINGRA_PREMIUM_REF?.trim() || "master";

function shouldInstallPremium() {
  if (!installPremiumFlag) {
    return false;
  }

  const normalizedFlag = installPremiumFlag.trim().toLowerCase();
  return normalizedFlag === "1" || normalizedFlag === "true" || normalizedFlag === "yes";
}

function configureGitRewrite(baseUrl) {
  const normalizedBaseUrl = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const rewriteSources = [
    "ssh://git@github.com/",
    "git@github.com:",
    "https://github.com/",
    "git+https://github.com/",
  ];

  for (const source of rewriteSources) {
    try {
      execSync(`git config --global url."${normalizedBaseUrl}".insteadOf "${source}"`, {
        stdio: "ignore",
      });
    } catch (error) {
      console.warn(
        `Failed to configure git rewrite for ${source}:`,
        error instanceof Error ? error.message : error,
      );
    }
  }
}

const packageJsonPath = resolve(process.cwd(), "package.json");
const lockfilePath = resolve(process.cwd(), "package-lock.json");

console.log("=== Install With Optional Premium ===");
console.log("INSTALL_SINGRA_PREMIUM:", installPremiumFlag ?? "not set");
console.log("SINGRA_PREMIUM_REF:", premiumRef);

if (shouldInstallPremium()) {
  if (!pat) {
    console.error("ERROR: INSTALL_SINGRA_PREMIUM is enabled, but GITHUB_PAT is missing.");
    process.exit(1);
  }

  const premiumDependency = `git+https://x-oauth-basic:${pat}@github.com/einmalmaik/singra-premium.git#${premiumRef}`;

  configureGitRewrite(`https://x-oauth-basic:${pat}@github.com/`);

  try {
    const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
    packageJson.dependencies ??= {};
    packageJson.dependencies["@singra/premium"] = premiumDependency;

    writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);
    console.log(`Injected @singra/premium from ref "${premiumRef}" into package.json`);

    if (existsSync(lockfilePath)) {
      unlinkSync(lockfilePath);
      console.log("Deleted package-lock.json to allow a clean dependency resolution");
    }
  } catch (error) {
    console.error("Failed to inject premium dependency:", error);
    process.exit(1);
  }
} else if (!pat) {
  configureGitRewrite("https://github.com/");
}

console.log("Running npm install...");
try {
  execSync("npm install", { stdio: "inherit" });
  console.log("npm install completed successfully");
} catch {
  console.error("npm install failed");
  process.exit(1);
}
