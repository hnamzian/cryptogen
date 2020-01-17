const fs = require('fs-extra');
const path = require('path');
var forge = require('node-forge');
var pki = forge.pki;
forge.options.usePureJavaScript = true;

const subjectsPath = 'subjects.json';
const pathsPath = 'paths.json';

function issueCaCert(caSubject) {
  var keys = pki.rsa.generateKeyPair(2048);
  var cert = pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  var attrs = getAttributes(caSubject);

  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey);

  var pem_pkey = pki.privateKeyToPem(keys.privateKey);
  var pem_cert = pki.certificateToPem(cert);

  return {
    cert: pem_cert,
    pkey: pem_pkey
  };
}

function issueClientCert(caCert, caKey, caSubject, clientSubject) {
  var attrsSubject = getAttributes(clientSubject);
  var attrsIssuer = getAttributes(caSubject);

  privateCAKey = pki.privateKeyFromPem(caKey);

  var keys = forge.pki.rsa.generateKeyPair(2048);
  var cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '02';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.setSubject(attrsSubject);
  cert.setIssuer(attrsIssuer);

  cert.sign(privateCAKey);

  var pem_pkey = pki.privateKeyToPem(keys.privateKey);
  var pem_cert = pki.certificateToPem(cert);

  return {
    cert: pem_cert,
    pkey: pem_pkey
  };
}

function getAttributes(subject) {
  let attrs = [];
  for (let key in subject) {
    attrs.push({ shortName: key, value: subject[key] });
  }
  return attrs;
}

function writeFile(content, paths, name) {
  for (let pathItem of paths) {
    const pathName = path.join(pathItem, name);
    fs.mkdirpSync(pathItem);
    fs.writeFileSync(pathName, content);
  }
}

function main() {
  const pkiPaths = JSON.parse(fs.readFileSync(pathsPath).toString());

  const subjects = JSON.parse(fs.readFileSync(subjectsPath).toString());
  const peerOrganizationsSubjects = subjects.peerOrganizations;
  const ordererSubjects = subjects.orderer;

  const caSubject = peerOrganizationsSubjects.ca;
  const caPKI = issueCaCert(caSubject);
  const caKeyName = pkiPaths.peerOrganizations.ca.key.name;
  const caKeyPaths = pkiPaths.peerOrganizations.ca.key.paths;
  const caCertName = pkiPaths.peerOrganizations.ca.cert.name;
  const caCertPaths = pkiPaths.peerOrganizations.ca.cert.paths;
  writeFile(caPKI.pkey, caKeyPaths, caKeyName);
  writeFile(caPKI.cert, caCertPaths, caCertName);

  for (let client in peerOrganizationsSubjects) {
    const clientPKI = issueClientCert(
      caPKI.cert,
      caPKI.pkey,
      caSubject,
      peerOrganizationsSubjects[client]
    );
    const clientKeyName = pkiPaths.peerOrganizations[client].key.name;
    const clientKeyPaths = pkiPaths.peerOrganizations[client].key.paths;
    const clientCertName = pkiPaths.peerOrganizations[client].cert.name;
    const clientCertPaths = pkiPaths.peerOrganizations[client].cert.paths;
    writeFile(clientPKI.pkey, clientKeyPaths, clientKeyName);
    writeFile(clientPKI.cert, clientCertPaths, clientCertName);
  }

  const caOrdererSubject = ordererSubjects.ca;
  const caOrdererPKI = issueCaCert(caOrdererSubject);
  const caOrdererKeyName = pkiPaths.ordererOrganizations.ca.key.name;
  const caOrdererKeyPaths = pkiPaths.ordererOrganizations.ca.key.paths;
  const caOrdererCertName = pkiPaths.ordererOrganizations.ca.cert.name;
  const caOrdererCertPaths = pkiPaths.ordererOrganizations.ca.cert.paths;
  writeFile(caOrdererPKI.pkey, caOrdererKeyPaths, caOrdererKeyName);
  writeFile(caOrdererPKI.cert, caOrdererCertPaths, caOrdererCertName);

  for (let client in ordererSubjects) {
    const clientPKI = issueClientCert(
      caOrdererPKI.cert,
      caOrdererPKI.pkey,
      caSubject,
      ordererSubjects[client]
    );
    const clientKeyName = pkiPaths.ordererOrganizations[client].key.name;
    const clientKeyPaths = pkiPaths.ordererOrganizations[client].key.paths;
    const clientCertName = pkiPaths.ordererOrganizations[client].cert.name;
    const clientCertPaths = pkiPaths.ordererOrganizations[client].cert.paths;
    writeFile(clientPKI.pkey, clientKeyPaths, clientKeyName);
    writeFile(clientPKI.cert, clientCertPaths, clientCertName);
  }
}

main();
