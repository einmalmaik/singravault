import { cpSync, existsSync, renameSync, rmSync } from "node:fs";
import { resolve } from "node:path";

function removeIfExists(targetPath) {
  if (existsSync(targetPath)) {
    rmSync(targetPath, { recursive: true, force: true });
  }
}

function stagePremiumSource(sourceArg, destinationArg) {
  if (!sourceArg || !destinationArg) {
    console.error("Usage: node scripts/stage-premium-source.mjs <source> <destination>");
    process.exit(1);
  }

  const sourcePath = resolve(process.cwd(), sourceArg);
  const destinationPath = resolve(process.cwd(), destinationArg);

  if (!existsSync(sourcePath)) {
    console.error(`Premium source checkout not found: ${sourcePath}`);
    process.exit(1);
  }

  removeIfExists(destinationPath);

  try {
    renameSync(sourcePath, destinationPath);
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "EXDEV") {
      throw error;
    }

    cpSync(sourcePath, destinationPath, { recursive: true });
    removeIfExists(sourcePath);
  }

  console.log(`Staged premium source from ${sourcePath} to ${destinationPath}`);
}

stagePremiumSource(process.argv[2], process.argv[3]);
