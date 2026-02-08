/**
 * HTTP Service
 *
 * HTTP request helper for OpenCode API.
 */

import * as http from 'http';
import { REQUEST_TIMEOUT_MS } from '../config';

/**
 * HTTP request result.
 */
export interface HttpResult {
  status: number | undefined;
  data: unknown;
}

/**
 * Make an HTTP request.
 */
export function httpRequest(
  options: http.RequestOptions,
  body: unknown = null
): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => (data += chunk.toString()));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: data ? JSON.parse(data) : null });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy();
      reject(new Error('Request timeout (5 min limit reached)'));
    });
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}
