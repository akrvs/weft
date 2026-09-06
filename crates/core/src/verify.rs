use crate::{
    Address, Error, Grant, Manifest, Pointer, Record, Result, Revoke, grant, manifest, pointer,
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
        _ => {}
    }
    if !record.self_signed() {
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
