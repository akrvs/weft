use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use weft_core::PublicKey;

use crate::login::{Refusal, Token};

pub const FILE: &str = "gateway/state.redb";
const SESSIONS: TableDefinition<&[u8; 32], (&[u8; 32], u64)> = TableDefinition::new("sessions");
const BUDGET: TableDefinition<&[u8; 32], (u64, u64)> = TableDefinition::new("budget");

#[derive(Debug)]
pub struct State {
    db: Database,
}

fn state(e: impl core::fmt::Display) -> Refusal {
    Refusal::State(e.to_string())
}

impl State {
    pub fn open(home: &Path) -> Result<Self, Refusal> {
        let path = home.join(FILE);
        if let Some(parent) = path.parent() {
            weft_home::fs::ensure_dir(parent).map_err(state)?;
        }
        let db = Database::create(&path).map_err(|e| state(format!("{}: {e}", path.display())))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(state)?;
        let tx = db.begin_write().map_err(state)?;
        tx.open_table(SESSIONS).map_err(state)?;
        tx.open_table(BUDGET).map_err(state)?;
        tx.commit().map_err(state)?;
        Ok(Self { db })
    }

    pub fn sessions(&self) -> Result<Vec<(Token, PublicKey, u64)>, Refusal> {
        let tx = self.db.begin_read().map_err(state)?;
        let table = tx.open_table(SESSIONS).map_err(state)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(state)? {
            let (token, value) = entry.map_err(state)?;
            let (author, expires) = value.value();
            let author = PublicKey::from_bytes(author).map_err(state)?;
            out.push((*token.value(), author, expires));
        }
        Ok(out)
    }

    pub fn put_session(
        &self,
        token: &Token,
        author: &PublicKey,
        expires: u64,
    ) -> Result<(), Refusal> {
        let tx = self.db.begin_write().map_err(state)?;
        tx.open_table(SESSIONS)
            .map_err(state)?
            .insert(token, (author.bytes(), expires))
            .map_err(state)?;
        tx.commit().map_err(state)
    }

    pub fn remove_sessions<'a>(
        &self,
        tokens: impl IntoIterator<Item = &'a Token>,
    ) -> Result<(), Refusal> {
        let tx = self.db.begin_write().map_err(state)?;
        {
            let mut table = tx.open_table(SESSIONS).map_err(state)?;
            for token in tokens {
                table.remove(token).map_err(state)?;
            }
        }
        tx.commit().map_err(state)
    }

    pub fn spends(&self) -> Result<Vec<([u8; 32], u64, u64)>, Refusal> {
        let tx = self.db.begin_read().map_err(state)?;
        let table = tx.open_table(BUDGET).map_err(state)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(state)? {
            let (author, value) = entry.map_err(state)?;
            let (since, bytes) = value.value();
            out.push((*author.value(), since, bytes));
        }
        Ok(out)
    }

    pub fn put_spend(&self, author: &[u8; 32], since: u64, bytes: u64) -> Result<(), Refusal> {
        let tx = self.db.begin_write().map_err(state)?;
        tx.open_table(BUDGET).map_err(state)?.insert(author, (since, bytes)).map_err(state)?;
        tx.commit().map_err(state)
    }

    pub fn remove_spends<'a>(
        &self,
        authors: impl IntoIterator<Item = &'a [u8; 32]>,
    ) -> Result<(), Refusal> {
        let tx = self.db.begin_write().map_err(state)?;
        {
            let mut table = tx.open_table(BUDGET).map_err(state)?;
            for author in authors {
                table.remove(author).map_err(state)?;
            }
        }
        tx.commit().map_err(state)
    }
}
