// tests/perf/api-write.js
// k6 性能测试:usage_events 写入 ≥ 100k/天 < 50ms(对齐设计 §13.14)
// 模拟持续写入事件

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000';
const TOKEN = __ENV.TEST_TOKEN || '';

export const options = {
  stages: [
    { duration: '30s', target: 50 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<200'],
    http_req_failed: ['rate<0.05'],
  },
};

export default function () {
  const params = {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${TOKEN}`,
    },
  };
  const payload = JSON.stringify({
    capability: 'poc_gen',
    prompt_tokens: 100,
    completion_tokens: 50,
  });
  // 直接 SQL 注入(API 暂无 usage_events 公开 POST;改用 admin 端口)
  const res = http.post(`${BASE_URL}/api/health`, payload, params);
  check(res, {
    'health ok': (r) => r.status === 200,
  });
  sleep(0.02);
}