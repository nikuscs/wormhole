use jiff::Timestamp;
use redb::{Durability, ReadableDatabase as _, ReadableTable as _};
use subtle::ConstantTimeEq as _;

use crate::db::{
    AuthorizedKey, DbError, EnrollmentInvite, INVITES, KEYS, RelayDb, decode, encode, redb_error,
};

impl RelayDb {
    pub fn put_invite(&self, invite: &EnrollmentInvite) -> Result<bool, DbError> {
        let encoded = encode(invite)?;
        let mut transaction = self.database.begin_write().map_err(redb_error)?;
        transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
        {
            let mut table = transaction.open_table(INVITES).map_err(redb_error)?;
            if table.get(invite.id.as_str()).map_err(redb_error)?.is_some() {
                return Ok(false);
            }
            table.insert(invite.id.as_str(), encoded.as_slice()).map_err(redb_error)?;
        }
        transaction.commit().map_err(redb_error)?;
        Ok(true)
    }

    pub fn list_invites(&self) -> Result<Vec<EnrollmentInvite>, DbError> {
        let transaction = self.database.begin_read().map_err(redb_error)?;
        let table = transaction.open_table(INVITES).map_err(redb_error)?;
        let mut invites: Vec<EnrollmentInvite> = Vec::new();
        for entry in table.iter().map_err(redb_error)? {
            let (_, value) = entry.map_err(redb_error)?;
            invites.push(decode(value.value())?);
        }
        invites.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(invites)
    }

    pub fn revoke_invite(&self, id: &str) -> Result<bool, DbError> {
        let mut transaction = self.database.begin_write().map_err(redb_error)?;
        transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
        let changed = {
            let mut table = transaction.open_table(INVITES).map_err(redb_error)?;
            let Some(stored) = table.get(id).map_err(redb_error)? else {
                return Ok(false);
            };
            let mut invite: EnrollmentInvite = decode(stored.value())?;
            drop(stored);
            invite.revoked = true;
            let encoded = encode(&invite)?;
            table.insert(id, encoded.as_slice()).map_err(redb_error)?;
            true
        };
        transaction.commit().map_err(redb_error)?;
        Ok(changed)
    }

    pub fn redeem_invite(
        &self,
        id: &str,
        secret_sha256: &str,
        now: i64,
        fingerprint: &str,
        public_key: &str,
    ) -> Result<bool, DbError> {
        let mut transaction = self.database.begin_write().map_err(redb_error)?;
        transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
        let (encoded_invite, encoded_key) = {
            let table = transaction.open_table(INVITES).map_err(redb_error)?;
            let Some(stored) = table.get(id).map_err(redb_error)? else {
                return Ok(false);
            };
            let mut invite: EnrollmentInvite = decode(stored.value())?;
            let secret_matches = invite.secret_sha256.len() == secret_sha256.len()
                && bool::from(invite.secret_sha256.as_bytes().ct_eq(secret_sha256.as_bytes()));
            let available = invite.max_uses.is_none_or(|maximum| invite.uses < maximum);
            let unexpired = invite.expires_at.is_none_or(|expiry| now <= expiry);
            if !secret_matches || invite.revoked || !available || !unexpired {
                return Ok(false);
            }
            invite.uses = invite
                .uses
                .checked_add(1)
                .ok_or_else(|| DbError::Data("invite usage count overflow".to_owned()))?;
            let key = AuthorizedKey {
                pub_b64: public_key.to_owned(),
                name: invite.name.clone(),
                created: Timestamp::from_second(now)
                    .map_err(|error| DbError::Data(error.to_string()))?,
                revoked: false,
            };
            (encode(&invite)?, encode(&key)?)
        };
        {
            let mut invites = transaction.open_table(INVITES).map_err(redb_error)?;
            invites.insert(id, encoded_invite.as_slice()).map_err(redb_error)?;
        }
        {
            let mut keys = transaction.open_table(KEYS).map_err(redb_error)?;
            keys.insert(fingerprint, encoded_key.as_slice()).map_err(redb_error)?;
        }
        transaction.commit().map_err(redb_error)?;
        Ok(true)
    }
}
