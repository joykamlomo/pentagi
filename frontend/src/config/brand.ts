/**
 * Single source of truth for product branding in the UI.
 * Override at build time with VITE_APP_NAME; never hardcode the product name elsewhere.
 */
export const BRAND_NAME: string = import.meta.env.VITE_APP_NAME || 'Security Agent';
