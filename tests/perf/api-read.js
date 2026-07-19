// tests/perf/api-read.js
// k6 性能测试:GET /customers P95 < 100ms(对齐设计 §13.14)
// 用法:k6 run tests/perf/api-read.js

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const TOKEN = __ENV.TEST_TOKEN || '';

export const options = {
  stages: [
    { duration: '10s', target: 10 },
    { duration: '30s', target: 50 },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<100'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const params = {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${TOKEN}`,
    },
  };
  const res = http.get(`${BASE_URL}/api/provider/v1/customers?size=20`, params);
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
  sleep(0.1);
}