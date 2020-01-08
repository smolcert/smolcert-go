use super::*;

#[cfg(feature="std")]
use std::time::{UNIX_EPOCH, SystemTime};
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
    pool
  }

  pub fn add_certificate(&mut self, cert: &'a Certificate) {
    self.cert_subject_map.insert(cert.subject.clone(), cert);
  }

  pub fn validate(&self, cert: &Certificate) -> Result<()> {
    match self.cert_subject_map.get(&cert.issuer) {
      Some(issuer_cert) => {
        cert.verify_signature(&issuer_cert.public_key)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        cert.validity.is_valid(now)?;
        // TODO validate more
      },
      None => return Err(Error{
        code: ErrorCode::ValidationError(ValidationErrorCode::Untrusted),
      }),
    };
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use rand::rngs::OsRng;

  #[test]
  fn test_cert_pool_validate_single_cert() {
    let mut csprng = OsRng{};
    let root_keypair: Keypair = Keypair::generate(&mut csprng);
    let root_cert = Certificate::new_self_signed(1, &"connctd", Validity::empty(), &"connctd", vec![], &root_keypair).unwrap();

    let root_certs = [root_cert];
    let cert_pool = CertificatePool::new(&root_certs[..]);

    let client_keypair = Keypair::generate(&mut csprng);
    let client_cert = Certificate::new(2, &"connctd", Validity::empty(), &"client 1", vec![], &client_keypair, &root_keypair).unwrap();

    cert_pool.validate(&client_cert).unwrap();
  }
}
