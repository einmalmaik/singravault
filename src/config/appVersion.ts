export const APP_VERSION = __APP_VERSION__;
export const APP_VERSION_SOURCE = __APP_VERSION_SOURCE__;

export const APP_VERSION_DISPLAY = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(APP_VERSION)
  ? `v${APP_VERSION}`
  : APP_VERSION;
