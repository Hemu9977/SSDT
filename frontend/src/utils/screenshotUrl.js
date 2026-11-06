import { API_BASE } from '../config/api';

/**
 * The page screenshot's <img> source. The in-house page capture stores an API
 * path (`/api/scan/screenshot/<token>.jpg`, served by the backend); anything
 * else (a data: URL, an absolute URL from an older scan) is used as it is.
 */
export function screenshotUrl(src) {
  if (!src || typeof src !== 'string') return null;
  return src.startsWith('/api/') ? `${API_BASE}${src}` : src;
}
