use crate::{
    Address, Challenge, Error, Grant, Manifest, Pointer, Receipt, Record, Recovery, Result, Revoke,
    grant, login, manifest, pointer, receipt, recovery,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub address: Address,
    pub author: Address,
    pub signer: Address,
    pub kind: String,
}

pub fn verify(record: &Record, manifest: Option<&Manifest>) -> Result<Verified> {
    record.check_signature()?;
    match record.kind() {
        manifest::KIND => {
            Manifest::from_record(record)?;
        }
        pointer::KIND => {
            Pointer::from_record(record)?;
        }
        grant::KIND => {
            Grant::from_record(record)?;
        }
        grant::REVOKE => {
            Revoke::from_record(record)?;
        }
        receipt::KIND => {
            Receipt::from_record(record)?;
        }
        login::KIND => {
            Challenge::from_record(record)?;
        }
        recovery::KIND => {
            let recovery = Recovery::from_record(record)?;
            let manifest = manifest.ok_or(Error::Unauthorized)?;
            recovery.authorize(record.author(), manifest)?;
        }
        _ => {}
    }
    if !record.self_signed() && record.kind() != recovery::KIND {
        let manifest = manifest.ok_or(Error::Unauthorized)?;
        manifest.authorizes(record.signer(), record.created())?;
    }
    Ok(Verified {
        address: record.address(),
        author: record.author().address(),
        signer: record.signer().address(),
        kind: record.kind().to_owned(),
    })
}
