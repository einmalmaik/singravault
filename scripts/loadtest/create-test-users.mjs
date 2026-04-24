import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { createClient } from '@supabase/supabase-js';

function argValue(flag, fallback) {
  const idx = process.argv.indexOf(flag);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function intValue(flag, fallback) {
  const raw = argValue(flag, String(fallback));
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`Invalid integer for ${flag}: ${raw}`);
  }
  return parsed;
}

function requiredEnvAny(names) {
  for (const name of names) {
    const value = process.env[name];
    if (value && value.trim()) {
      return value.trim();
    }
  }
  throw new Error(`Missing one of env vars: ${names.join(', ')}`);
}

async function ensureDirForFile(filePath) {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
}

async function listAllUsers(adminClient) {
  const all = [];
  let page = 1;
  const perPage = 1000;

  while (true) {
    const { data, error } = await adminClient.auth.admin.listUsers({
      page,
      perPage,
    });

    if (error) {
      throw new Error(`Failed to list users (page ${page}): ${error.message}`);
    }

    const users = data?.users ?? [];
    all.push(...users);

    if (users.length < perPage) {
      break;
    }
    page += 1;
  }

  return all;
}

function buildEmail(index, prefix, domain) {
  const padded = String(index).padStart(5, '0');
  return `${prefix}${padded}@${domain}`;
}

async function main() {
  const supabaseUrl = requiredEnvAny(['SUPABASE_URL', 'VITE_SUPABASE_URL']);
  const serviceRoleKey = requiredEnvAny(['SUPABASE_SERVICE_ROLE_KEY']);

  const count = intValue('--count', Number(process.env.TEST_USERS_COUNT || 50));
  const startIndex = intValue('--start-index', Number(process.env.TEST_USERS_START_INDEX || 1));
  const emailPrefix = argValue('--prefix', process.env.TEST_USERS_EMAIL_PREFIX || 'loadtest.user.');
  const emailDomain = argValue('--domain', process.env.TEST_USERS_EMAIL_DOMAIN || 'example.test');
  const outputPath = path.resolve(
    process.cwd(),
    argValue('--output', process.env.LOADTEST_USERS_FILE || 'loadtest/users.txt'),
  );

  const adminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });

  const existingUsers = await listAllUsers(adminClient);
  const existingEmails = new Set(
    existingUsers.map((user) => user.email).filter((email) => typeof email === 'string'),
  );

  const targetUsers = [];
  for (let i = 0; i < count; i += 1) {
    const index = startIndex + i;
    targetUsers.push({
      index,
      email: buildEmail(index, emailPrefix, emailDomain),
    });
  }

  let created = 0;
  for (const user of targetUsers) {
    if (existingEmails.has(user.email)) {
      continue;
    }

    const { error } = await adminClient.auth.admin.createUser({
      email: user.email,
      email_confirm: true,
      user_metadata: {
        loadtest: true,
        loadtest_index: user.index,
      },
    });

    if (error) {
      throw new Error(`Failed to create user ${user.email}: ${error.message}`);
    }

    existingEmails.add(user.email);
    created += 1;
  }

  await ensureDirForFile(outputPath);
  const userLines = targetUsers.map((entry) => entry.email);
  await fs.writeFile(outputPath, `${userLines.join('\n')}\n`, 'utf8');

  console.log(`Seed complete. Requested: ${count}, created: ${created}, existing: ${count - created}`);
  console.log(`Users file written: ${outputPath}`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
