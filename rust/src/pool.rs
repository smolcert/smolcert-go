use super::*;

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CertificatePool<'a> {
  cert_subject_map: HashMap<String,&'a Certificate>,
}

impl<'a> CertificatePool<'a> {
  pub fn new(certs: &'a [Certificate]) -> Self {
    let mut pool = CertificatePool{
      cert_subject_map: HashMap::new(),
    };
    for cert in certs {
      pool.cert_subject_map.insert(cert.subject.clone(), cert);
    }
    return pool;
  }

  pub fn add_certificate(&mut self, cert: &'a Certificate) {
    self.cert_subject_map.insert(cert.subject.clone(), cert);
  }

  pub fn validate(&self, cert: &Certificate) -> Result<()> {
    match self.cert_subject_map.get(&cert.issuer) {
      Some(issuer_cert) => {
        cert.verify_signature(&issuer_cert.public_key)?;
        // TODO validate more
      },
      None => return Err(Error{
        code: ErrorCode::ValidationError(ValidationErrorCode::Untrusted),
      }),
    };
    Ok(())
  }
}
