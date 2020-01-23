use super::*;

#[cfg(feature="std")]
use std::time::{UNIX_EPOCH, SystemTime};
use std::collections::HashMap;

#[derive(Debug)]
pub struct CertificatePool<'c> 
{
  cert_subject_map: HashMap<String, &'c Certificate<'c>>,
}

impl<'c> CertificatePool<'c> 
{
  pub fn new(certs: &'c [Certificate]) -> Self {
    let mut pool = CertificatePool{
      cert_subject_map: HashMap::new(),
    };
    for cert in certs {
      pool.cert_subject_map.insert(cert.subject.to_owned(), cert);
    }
    pool
  }

  pub fn add_certificate(&mut self, cert: &'c Certificate) {
    self.cert_subject_map.insert(cert.subject.to_owned(), cert);
  }

  #[cfg(feature="std")]
  pub fn validate(&self, cert: &mut Certificate) -> Result<()> {
    match self.cert_subject_map.get(&cert.issuer.to_owned()) {
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
    let mut client_cert = Certificate::new(2, &"connctd", Validity::empty(), &"client 1", vec![], &client_keypair, &root_keypair).unwrap();

    cert_pool.validate(&mut client_cert).unwrap();
  }
}
