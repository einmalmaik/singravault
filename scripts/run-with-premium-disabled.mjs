import { rmSync } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const [, , command, ...args] = process.argv;
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

if (!command) {
  console.error("Missing command. Usage: node scripts/run-with-premium-disabled.mjs <command> [...args]");
  process.exit(1);
}

if (command === "vite" && args[0] === "build") {
  rmSync(path.join(workspaceRoot, "dist"), { recursive: true, force: true });
}

const child = spawn(command, args, {
  stdio: "inherit",
  shell: process.platform === "win32",
  env: {
    ...process.env,
    SINGRA_DISABLE_PREMIUM: "true",
  },
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code ?? 1);
});
