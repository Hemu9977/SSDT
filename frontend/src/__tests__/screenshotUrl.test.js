import { screenshotUrl } from '../utils/screenshotUrl';
import { API_BASE } from '../config/api';

// The in-house page capture stores the screenshot as an API path; both scan
// panels (Hero, AuthenticatedScanPanel) render it with a plain <img>.
test('an in-house screenshot path is served from the API origin', () => {
  const path = `/api/scan/screenshot/${'a'.repeat(64)}.jpg`;
  expect(screenshotUrl(path)).toBe(`${API_BASE}${path}`);
});

test('other sources are used as they are; nothing becomes null', () => {
  expect(screenshotUrl('data:image/png;base64,AAAA')).toBe('data:image/png;base64,AAAA');
  expect(screenshotUrl('https://example.test/shot.png')).toBe('https://example.test/shot.png');
  expect(screenshotUrl(null)).toBeNull();
  expect(screenshotUrl(undefined)).toBeNull();
  expect(screenshotUrl({})).toBeNull();
});
