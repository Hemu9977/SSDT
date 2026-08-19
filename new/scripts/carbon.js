import https from 'https';
import middleware from './_common/middleware.js';

const carbonHandler = async (url) => {

  // First, get the size of the website's HTML
  const getHtmlSize = (url) => new Promise((resolve, reject) => {
    https.get(url, res => {
      let data = '';
      res.on('data', chunk => {
        data += chunk;
      });
      res.on('end', () => {
        const sizeInBytes = Buffer.byteLength(data, 'utf8');
        resolve(sizeInBytes);
      });
    }).on('error', reject);
  });

  try {
    const sizeInBytes = await getHtmlSize(url);
    const apiUrl = `https://api.websitecarbon.com/data?bytes=${sizeInBytes}&green=0`;

    // Then use that size to get the carbon data
    const carbonData = await new Promise((resolve, reject) => {
      const req = https.get(apiUrl, res => {
        let data = '';
        res.on('data', chunk => {
          data += chunk;
        });
        res.on('end', () => {
          // JSON.parse must never throw out of this handler. The Promise executor has
          // already returned by the time 'end' fires, so a throw here does not reject the
          // promise and is not caught by the try/catch below — it escapes as an
          // uncaughtException and kills the entire WebCheck process. api.websitecarbon.com
          // intermittently answers with a Cloudflare "Just a moment..." HTML interstitial
          // instead of JSON, which crashed the container 34 times in the 30 days to
          // 2026-08-19. Reject instead: middleware already turns a rejection into a 5xx
          // for this one endpoint, and the rest of the scan continues.
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(new Error(`carbon API returned HTTP ${res.statusCode}`));
          }
          try {
            resolve(JSON.parse(data));
          } catch {
            const contentType = res.headers['content-type'] || 'unknown';
            const snippet = data.slice(0, 80).replace(/\s+/g, ' ').trim();
            reject(new Error(`carbon API returned non-JSON (content-type: ${contentType}): ${snippet}`));
          }
        });
      }).on('error', reject);
      // A challenge page can also just hang. Without this the socket is held until the
      // OS gives up, and the scan's carbon step never settles.
      req.setTimeout(15000, () => req.destroy(new Error('carbon API timed out after 15s')));
    });

    if (!carbonData.statistics || (carbonData.statistics.adjustedBytes === 0 && carbonData.statistics.energy === 0)) {
      return {
        statusCode: 200,
        body: JSON.stringify({ skipped: 'Not enough info to get carbon data' }),
      };
    }

    carbonData.scanUrl = url;
    return carbonData;
  } catch (error) {
    throw new Error(`Error: ${error.message}`);
  }
};

export const handler = middleware(carbonHandler);
export default handler;
