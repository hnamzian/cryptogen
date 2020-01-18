module.exports = certificate => {
  if (!certificate.startsWith('-----BEGIN CERTIFICATE-----')) {
    certificate =
      '-----BEGIN CERTIFICATE-----\n' +
      certificate +
      '\n-----END CERTIFICATE-----'
  }
  return certificate
}
