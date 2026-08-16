const axios = require('axios');

/**
 * Get PageSpeed Insights report for a given URL
 * @param {string} url - The URL to analyze
 * @returns {Promise<Object>} - PageSpeed Insights report data
 */
async function getPageSpeedReport(url) {
  try {
    const apiKey = process.env.PSI_API_KEY;

    if (!apiKey) {
      throw new Error('PSI_API_KEY is not configured in environment variables');
    }

    // PageSpeed Insights API endpoint
    const endpoint = 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed';

    // Make request to PageSpeed Insights API.
    //
    // `category` MUST be sent as a repeated key (category=a&category=b). Axios'
    // default serializer emits `category[]=a&category[]=b`, which the PSI v5 API
    // does not recognise — it silently ignores the unknown parameter and falls
    // back to its default of returning ONLY the performance category. That is why
    // accessibility / best-practices / SEO came back missing (and were rendered as
    // "0/100"). Serialize explicitly so all four categories are actually requested.
    const response = await axios.get(endpoint, {
      params: {
        url: url,
        key: apiKey,
        category: ['performance', 'accessibility', 'best-practices', 'seo'],
        strategy: 'desktop'
      },
      paramsSerializer: {
        serialize: (params) => {
          const search = new URLSearchParams();
          for (const [key, value] of Object.entries(params)) {
            if (value === undefined || value === null) continue;
            if (Array.isArray(value)) {
              value.forEach(v => search.append(key, v));
            } else {
              search.append(key, value);
            }
          }
          return search.toString();
        }
      }
    });

    return response.data;
  } catch (error) {
    console.error('Error fetching PageSpeed report:', error.message);

    if (error.response) {
      // API returned an error response
      throw new Error(`PageSpeed API error: ${error.response.status} - ${error.response.data.error?.message || 'Unknown error'}`);
    } else if (error.request) {
      // Request was made but no response received
      throw new Error('No response from PageSpeed API');
    } else {
      // Something else went wrong
      throw new Error(`PageSpeed service error: ${error.message}`);
    }
  }
}

module.exports = {
  getPageSpeedReport
};
