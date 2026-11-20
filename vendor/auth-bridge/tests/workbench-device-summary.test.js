import assert from 'node:assert/strict';
import test from 'node:test';

import { checkSessionHealth } from '../src/session-network.js';

async function healthFor(devices, deviceStatus = 200) {
  const routes = [];
  const fetchImpl = async url => {
    const route = new URL(url).pathname;
    routes.push(route);
    if (route === '/backend-api/wham/usage') {
      return Response.json({ rate_limit: { primary_window: { used_percent: 4 } } });
    }
    assert.equal(route, '/backend-api/accounts/sessions');
    return Response.json({ devices }, { status: deviceStatus });
  };
  const result = await checkSessionHealth({ accessToken: 'synthetic-fixture' }, { fetchImpl, includeDevices: true, includeUsage: true });
  assert.deepEqual(routes, ['/backend-api/wham/usage', '/backend-api/accounts/sessions']);
  return result;
}

test('counts returned records on all devices and aggregates their login times', async () => {
  const result = await healthFor([
    { app_sessions: [{ client_name: 'Test' }, { client_name: 'Test' }], session_created_at_seconds: '1780000000', last_signed_in_timestamp_second: 1781000000 },
    { app_sessions: [{ last_seen_at: 1781000000, session_id: 'fixture-private-id' }], session_created_at_seconds: 1780900000, last_signed_in_timestamp_second: 1781200000 },
  ]);
  assert.equal(result.deviceCount, 2);
  assert.equal(result.appSessionCount, 3);
  assert.equal(result.firstLoginAt, 1780000000000);
  assert.equal(result.lastLoginAt, 1781200000000);
  assert.equal(JSON.stringify(result).includes('fixture-private-id'), false);
});

test('distinguishes zero records from incomplete device rows or rejected access', async () => {
  for (const devices of [[], [{ app_sessions: [] }]]) {
    const result = await healthFor(devices);
    assert.equal(result.deviceCount, devices.length);
    assert.equal(result.appSessionCount, 0);
  }
  for (const incomplete of [{}, { app_sessions: null }, { app_sessions: [{}] }, { app_sessions: [null] }, { app_sessions: ['Test'] }]) {
    const result = await healthFor([{ app_sessions: [{ client_name: 'known' }] }, incomplete]);
    assert.equal(result.appSessionCount, null);
    assert.equal(result.deviceCount, 2);
  }
  const unavailable = await healthFor([{ app_sessions: [] }], 403);
  assert.equal(unavailable.devicesStatus, 403);
  assert.equal(unavailable.appSessionCount, null);
  assert.equal(unavailable.deviceCount, null);
  assert.equal(unavailable.firstLoginAt, null);
  assert.equal(unavailable.status, 200);
});
