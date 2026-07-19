import { createSign, createVerify, generateKeyPairSync, randomUUID, createHash, createPrivateKey, createPublicKey } from 'crypto';

/**
 * 极简 SAML 2.0 工具(无外部依赖,自签 RSA-SHA256)
 * 仅支持 HTTP-POST Binding + AuthnRequest/Response 流程
 * 真实生产环境推荐 @node-saml/node-saml 或 samlify
 */

let keyPair: { privateKey: any; publicKey: any } | null = null;

function getOrCreateKeyPair() {
  if (!keyPair) {
    keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  }
  return keyPair;
}

export function getSamlPrivateKeyPem(): string {
  return getOrCreateKeyPair().privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
}

export function getSamlPublicKeyPem(): string {
  return getOrCreateKeyPair().publicKey.export({ type: 'spki', format: 'pem' }) as string;
}

function base64UrlEncode(buf: Buffer | string): string {
  const b = typeof buf === 'string' ? Buffer.from(buf) : buf;
  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(s: string): Buffer {
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad), 'base64');
}

function randomId(): string {
  return '_' + randomUUID().replace(/-/g, '');
}

function isoNow(): string {
  return new Date().toISOString();
}

function isoMinusSeconds(sec: number): string {
  return new Date(Date.now() - sec * 1000).toISOString();
}

function isoPlusMinutes(min: number): string {
  return new Date(Date.now() + min * 60_000).toISOString();
}

export function generateSamlAuthnRequest(opts: {
  spEntityId: string;
  idpSsoUrl: string;
  acsUrl: string;
  nameIdFormat?: string;
  relayState?: string;
}): { url: string; id: string } {
  const id = randomId();
  const issueInstant = isoNow();
  const params = new URLSearchParams({
    SAMLRequest: base64UrlEncode(buildAuthnRequestXml({
      id, issueInstant, spEntityId: opts.spEntityId, acsUrl: opts.acsUrl,
      nameIdFormat: opts.nameIdFormat ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    })),
  });
  if (opts.relayState) params.set('RelayState', opts.relayState);
  return { url: `${opts.idpSsoUrl}?${params.toString()}`, id };
}

function buildAuthnRequestXml(opts: {
  id: string;
  issueInstant: string;
  spEntityId: string;
  acsUrl: string;
  nameIdFormat: string;
}): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${opts.id}" Version="2.0" IssueInstant="${opts.issueInstant}"
  Destination="" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  AssertionConsumerServiceURL="${opts.acsUrl}">
  <saml:Issuer>${opts.spEntityId}</saml:Issuer>
  <samlp:NameIDPolicy Format="${opts.nameIdFormat}" AllowCreate="true"/>
</samlp:AuthnRequest>`;
}

export function parseSamlResponse(opts: {
  samlResponseB64: string;
  expectedAudience: string;
  expectedRecipient?: string;
  idpPublicKeyPem: string;
}): {
  valid: boolean;
  reason?: string;
  nameId?: string;
  email?: string;
  attributes: Record<string, string>;
  sessionIndex?: string;
} {
  let xml: string;
  try {
    xml = base64UrlDecode(opts.samlResponseB64).toString('utf-8');
  } catch (e: any) {
    return { valid: false, reason: `decode failed: ${e.message}`, attributes: {} };
  }
  const assertions = xml.match(/<saml:Assertion[^>]*>([\s\S]*?)<\/saml:Assertion>/);
  if (!assertions) return { valid: false, reason: 'no Assertion element', attributes: {} };
  const assertion = assertions[1];

  if (!verifyXmlSignature(assertion, opts.idpPublicKeyPem)) {
    return { valid: false, reason: 'signature verification failed', attributes: {} };
  }

  const conditions = assertion.match(/<saml:Conditions[^>]*>([\s\S]*?)<\/saml:Conditions>/);
  if (conditions) {
    const condXml = conditions[1];
    const audMatch = condXml.match(/<saml:AudienceRestriction>[\s\S]*?<saml:Audience>([^<]+)<\/saml:Audience>/);
    if (audMatch && audMatch[1] !== opts.expectedAudience) {
      return { valid: false, reason: `audience mismatch: ${audMatch[1]}`, attributes: {} };
    }
  }

  const subject = assertion.match(/<saml:Subject>[\s\S]*?<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/);
  const nameId = subject?.[1];

  const attrs: Record<string, string> = {};
  const attrRegex = /<saml:Attribute[^>]*Name="([^"]+)"[^>]*>[\s\S]*?<saml:AttributeValue>([^<]+)<\/saml:AttributeValue>/g;
  let m: RegExpExecArray | null;
  while ((m = attrRegex.exec(assertion)) !== null) {
    attrs[m[1]] = m[2];
  }
  const email = attrs['email'] ?? attrs['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] ?? nameId;

  const sessionIndexMatch = assertion.match(/<saml:AuthnStatement[^>]*SessionIndex="([^"]+)"/);
  const sessionIndex = sessionIndexMatch?.[1];

  return { valid: true, nameId, email, attributes: attrs, sessionIndex };
}

function verifyXmlSignature(xmlFragment: string, publicKeyPem: string): boolean {
  const signedInfoMatch = xmlFragment.match(/<ds:SignedInfo[^>]*>([\s\S]*?)<\/ds:SignedInfo>/);
  const signatureMatch = xmlFragment.match(/<ds:SignatureValue[^>]*>([^<]+)<\/ds:SignatureValue>/);
  if (!signedInfoMatch || !signatureMatch) {
    return verifySimpleSignature(xmlFragment, publicKeyPem);
  }
  const signedInfo = signedInfoMatch[1];
  const signature = Buffer.from(signatureMatch[1].replace(/\s/g, ''), 'base64');
  const c14n = signedInfo.replace(/\s+xmlns="[^"]*"/g, '').replace(/>\s+</g, '><');
  const verifier = createVerify('RSA-SHA256');
  verifier.update(c14n);
  verifier.end();
  try {
    return verifier.verify(publicKeyPem, signature);
  } catch {
    return false;
  }
}

function verifySimpleSignature(xml: string, publicKeyPem: string): boolean {
  const idMatch = xml.match(/<saml:Assertion[^>]*ID="([^"]+)"/);
  if (!idMatch) return false;
  const signValMatch = xml.match(/<ds:SignatureValue[^>]*>([^<]+)<\/ds:SignatureValue>/);
  if (!signValMatch) return false;
  const data = idMatch[1];
  const sigB64 = signValMatch[1].replace(/\s/g, '');
  let sigBytes: Buffer;
  try {
    sigBytes = Buffer.from(sigB64, 'base64');
  } catch {
    try { sigBytes = Buffer.from(sigB64, 'hex'); } catch { return false; }
  }
  try {
    const priv = getSamlPrivateKeyPem();
    const signer = createSign('RSA-SHA256');
    signer.update(Buffer.from(data));
    signer.end();
    const expectedSig = signer.sign(priv).toString('base64');
    console.log('[saml-verify-debug] data:', JSON.stringify(data), '| actual length:', expectedSig.length, '| xml sig length:', sigB64.length, '| match:', expectedSig === sigB64);
    const verifier = createVerify('RSA-SHA256');
    verifier.update(Buffer.from(data));
    verifier.end();
    return verifier.verify(publicKeyPem, sigBytes);
  } catch (e: any) {
    console.error('[saml-verify-error]', e?.message);
    return false;
  }
}

export function generateMockSamlResponse(opts: {
  spEntityId: string;
  acsUrl: string;
  idpEntityId: string;
  recipient: string;
  user: { nameId: string; email?: string; attributes?: Record<string, string> };
  inResponseTo?: string;
  signWithKeyPem: string;
}): string {
  const id = randomId();
  const responseId = randomId();
  const assertionId = randomId();
  const issueInstant = isoNow();
  const notOnOrAfter = isoPlusMinutes(30);
  const user = opts.user;
  const attrs = user.attributes ?? {};
  const attrXml = Object.entries(attrs).map(([k, v]) =>
    `<saml:Attribute Name="${escapeXml(k)}"><saml:AttributeValue>${escapeXml(v)}</saml:AttributeValue></saml:Attribute>`,
  ).join('\n');
  const emailXml = user.email ? `<saml:Attribute Name="email"><saml:AttributeValue>${escapeXml(user.email)}</saml:AttributeValue></saml:Attribute>` : '';
  const nameXml = `<saml:Attribute Name="displayName"><saml:AttributeValue>${escapeXml(user.nameId)}</saml:AttributeValue></saml:Attribute>`;

  const signedInfoInner = `<ds:Reference URI="#${assertionId}"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference>`;
  const signedInfoXml = `<ds:SignedInfo>${signedInfoInner}</ds:SignedInfo>`;
  const assertionXml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">
<saml:Issuer>${escapeXml(opts.idpEntityId)}</saml:Issuer>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${signedInfoXml}<ds:SignatureValue>${generateSimpleSignature(opts.signWithKeyPem, signedInfoInner)}</ds:SignatureValue></ds:Signature>
<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${escapeXml(user.nameId)}</saml:NameID></saml:Subject>
<saml:Conditions NotBefore="${isoMinusSeconds(60)}" NotOnOrAfter="${notOnOrAfter}">
<saml:AudienceRestriction><saml:Audience>${escapeXml(opts.spEntityId)}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${id}">
<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
</saml:AuthnStatement>
${emailXml}
${nameXml}
${attrXml}
</saml:Assertion>`;

  const responseXml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${responseId}" Version="2.0" IssueInstant="${issueInstant}"
  Destination="${escapeXml(opts.recipient)}"${opts.inResponseTo ? ` InResponseTo="${escapeXml(opts.inResponseTo)}"` : ''}>
<saml:Issuer>${escapeXml(opts.idpEntityId)}</saml:Issuer>
${assertionXml}
</samlp:Response>`;
  return responseXml;
}

function generateSimpleSignature(privateKeyPem: string, signedInfoContent: string): string {
  const signer = createSign('RSA-SHA256');
  signer.update(Buffer.from(signedInfoContent, 'utf-8'));
  signer.end();
  return signer.sign(privateKeyPem).toString('base64');
}

function escapeXml(s: string): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

export function getSamlSpMetadata(opts: {
  spEntityId: string;
  acsUrl: string;
  spName?: string;
}): string {
  const cert = getSamlPublicKeyPem()
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\n/g, '');
  return `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${escapeXml(opts.spEntityId)}">
<SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true"
  protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  Location="${escapeXml(opts.acsUrl)}" index="0" isDefault="true"/>
<KeyDescriptor use="signing">
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
<X509Data><X509Certificate>${cert}</X509Certificate></X509Data>
</KeyInfo>
</KeyDescriptor>
</SPSSODescriptor>
</EntityDescriptor>`;
}
