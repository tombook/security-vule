import { Hono } from 'hono';
import { getSamlPrivateKeyPem, getSamlSpMetadata, generateMockSamlResponse, generateSamlAuthnRequest } from '../services/saml';
import { pool } from '../db/client';

export const mockIdpRoutes = new Hono()
  .get('/', (c) => {
    return c.html(`<html><body>
<h1>Mock SAML IdP</h1>
<p>This is a development-only SAML Identity Provider for testing SSO flows.</p>
<p>Login: <a href="/mock-idp/sso?SAMLRequest=mock&RelayState=mock">/mock-idp/sso?SAMLRequest=mock&RelayState=mock</a></p>
</body></html>`);
  })

  .get('/sso', (c) => {
    const samlRequest = c.req.query('SAMLRequest') ?? '';
    const relayState = c.req.query('RelayState') ?? '';

    if (!samlRequest) {
      return c.html('Missing SAMLRequest parameter', 400);
    }

    return c.html(`<!DOCTYPE html>
<html><head><title>Mock IdP - Sign in</title></head>
<body style="font-family: sans-serif; max-width: 480px; margin: 60px auto; padding: 24px;">
<h1>Mock SAML IdP</h1>
<p>签发测试用户 <code>alice.sso@demo.com</code>(会自动判定为 CustomerAdmin 角色)</p>
<form method="POST" action="/mock-idp/sso/post">
  <input type="hidden" name="SAMLRequest" value="${samlRequest.replace(/"/g, '&quot;')}" />
  <input type="hidden" name="RelayState" value="${relayState.replace(/"/g, '&quot;')}" />
  <p>Email: <input type="email" name="email" value="alice.sso@demo.com" required style="width:100%;padding:6px;margin:4px 0;" /></p>
  <p>Tenant ID: <input type="text" name="tenant_id" value="00000000-0000-0000-0000-000000000001" style="width:100%;padding:6px;margin:4px 0;" /></p>
  <p>Customer ID: <input type="text" name="customer_id" value="00000000-0000-0000-0000-000000000010" style="width:100%;padding:6px;margin:4px 0;" /></p>
  <p>Role: <select name="role" style="width:100%;padding:6px;margin:4px 0;">
    <option value="CustomerAdmin">CustomerAdmin</option>
    <option value="CustomerDeveloper">CustomerDeveloper</option>
    <option value="CustomerViewer">CustomerViewer</option>
    <option value="ProviderOwner">ProviderOwner</option>
  </select></p>
  <button type="submit" style="padding: 8px 20px; background: #4F46E5; color: white; border: none; border-radius: 4px; cursor: pointer;">登录(Sign in with SSO)</button>
</form>
</body></html>`);
  })

  .post('/sso/post', async (c) => {
    const form = await c.req.formData();
    const samlRequest = form.get('SAMLRequest') as string ?? '';
    const relayState = form.get('RelayState') as string ?? '';
    const email = form.get('email') as string ?? 'alice.sso@demo.com';
    const tenantId = form.get('tenant_id') as string ?? '00000000-0000-0000-0000-000000000001';
    const customerId = form.get('customer_id') as string ?? '';
    const role = form.get('role') as string ?? 'CustomerAdmin';

    const spEntityId = `https://security-vule.local/sso/sp/${tenantId}`;
    const acsUrl = `http://localhost:3000/api/auth/sso/acs`;

    const samlResponseXml = generateMockSamlResponse({
      spEntityId,
      acsUrl,
      idpEntityId: 'https://mock-idp.security-vule.local',
      recipient: acsUrl,
      user: {
        nameId: email,
        email,
        attributes: {
          email,
          displayName: email,
          role,
          tenant_id: tenantId,
          customer_id: customerId,
        },
      },
      signWithKeyPem: getSamlPrivateKeyPem(),
    });

    const samlResponseB64 = Buffer.from(samlResponseXml).toString('base64');

    return c.html(`<!DOCTYPE html>
<html><head><title>Mock IdP - Redirecting</title></head>
<body onload="document.forms[0].submit()" style="font-family: sans-serif;">
<form method="POST" action="${acsUrl}">
  <input type="hidden" name="SAMLResponse" value="${samlResponseB64}" />
  <input type="hidden" name="RelayState" value="${relayState.replace(/"/g, '&quot;')}" />
  <noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>`);
  });
