export interface ClientDevTestAccountConfig {
  showDevTestAccountUi: boolean;
  emailHint: string | null;
}

export function getClientDevTestAccountConfig(): ClientDevTestAccountConfig {
  const env = import.meta.env;
  return {
    showDevTestAccountUi: env.VITE_DEV_TEST_ACCOUNT_UI === 'true',
    emailHint: typeof env.VITE_DEV_TEST_EMAIL === 'string' && env.VITE_DEV_TEST_EMAIL.trim()
      ? env.VITE_DEV_TEST_EMAIL.trim()
      : null,
  };
}
