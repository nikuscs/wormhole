//! Quarantined webhook database transitions.

use jiff::Timestamp;
use redb::{Durability, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use uuid::Uuid;

use crate::{
    buffer::BufferedRequest,
    db::{
        BINDS, DbError, FailedWebhook, RelayDb, WEBHOOK_BUFFER, WEBHOOK_FAILED, WEBHOOK_SEQUENCE,
        buffer_key, decode, encode, parse_buffer_key, redb_error,
    },
};

impl RelayDb {
    pub fn prune_all_expired(&self) -> Result<(), DbError> {
        for (bind, record) in self.list_binds()? {
            if let crate::db::PersistedBindSpec::Http { buffer: Some(policy), .. } = record.spec {
                self.prune_expired(bind, policy.ttl_secs)?;
            }
        }
        Ok(())
    }

    pub fn delete_bind_data(&self, bind: Uuid) -> Result<(), DbError> {
        let mut transaction = self.database.begin_write().map_err(redb_error)?;
        transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
        let keys = |table: &redb::Table<&[u8], &[u8]>| -> Result<Vec<Vec<u8>>, DbError> {
            let mut keys = Vec::new();
            for entry in table.iter().map_err(redb_error)? {
                let (key, _) = entry.map_err(redb_error)?;
                if parse_buffer_key(key.value()).is_some_and(|(stored, _)| stored == bind) {
                    keys.push(key.value().to_vec());
                }
            }
            Ok(keys)
        };
        {
            let mut active = transaction.open_table(WEBHOOK_BUFFER).map_err(redb_error)?;
            for key in keys(&active)? {
                active.remove(key.as_slice()).map_err(redb_error)?;
            }
            let mut failed = transaction.open_table(WEBHOOK_FAILED).map_err(redb_error)?;
            for key in keys(&failed)? {
                failed.remove(key.as_slice()).map_err(redb_error)?;
            }
            transaction
                .open_table(BINDS)
                .map_err(redb_error)?
                .remove(bind.as_bytes().as_slice())
                .map_err(redb_error)?;
            transaction
                .open_table(WEBHOOK_SEQUENCE)
                .map_err(redb_error)?
                .remove(bind.as_bytes().as_slice())
                .map_err(redb_error)?;
        }
        transaction.commit().map_err(redb_error)
    }

    pub fn prune_expired(&self, bind: Uuid, ttl_secs: u64) -> Result<(), DbError> {
        let cutoff = jiff::Timestamp::now()
            .as_second()
            .saturating_sub(ttl_secs.try_into().unwrap_or(i64::MAX));
        let mut transaction = self.database.begin_write().map_err(redb_error)?;
        transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
        let mut active_expired = Vec::new();
        {
            let table = transaction.open_table(WEBHOOK_BUFFER).map_err(redb_error)?;
            for entry in table.iter().map_err(redb_error)? {
                let (key, value) = entry.map_err(redb_error)?;
                if parse_buffer_key(key.value()).is_some_and(|(stored, _)| stored == bind) {
                    let request: BufferedRequest = decode(value.value())?;
                    if request.received_at.as_second() <= cutoff {
                        active_expired.push(key.value().to_vec());
                    }
                }
            }
        }
        let mut failed_expired = Vec::new();
        {
            let table = transaction.open_table(WEBHOOK_FAILED).map_err(redb_error)?;
            for entry in table.iter().map_err(redb_error)? {
                let (key, value) = entry.map_err(redb_error)?;
                if parse_buffer_key(key.value()).is_some_and(|(stored, _)| stored == bind) {
                    let failed: FailedWebhook = decode(value.value())?;
                    if failed.request.received_at.as_second() <= cutoff {
                        failed_expired.push(key.value().to_vec());
                    }
                }
            }
        }
        {
            let mut active = transaction.open_table(WEBHOOK_BUFFER).map_err(redb_error)?;
            for key in active_expired {
                active.remove(key.as_slice()).map_err(redb_error)?;
            }
            let mut failed = transaction.open_table(WEBHOOK_FAILED).map_err(redb_error)?;
            for key in failed_expired {
                failed.remove(key.as_slice()).map_err(redb_error)?;
            }
        }
        transaction.commit().map_err(redb_error)
    }

    pub fn list_failed(&self) -> Result<Vec<(Uuid, u64, FailedWebhook)>, DbError> {
        let transaction = self.database.begin_read().map_err(redb_error)?;
        let table = transaction.open_table(WEBHOOK_FAILED).map_err(redb_error)?;
        let mut failed = Vec::new();
        for entry in table.iter().map_err(redb_error)? {
            let (key, value) = entry.map_err(redb_error)?;
            if let Some((bind, seq)) = parse_buffer_key(key.value()) {
                failed.push((bind, seq, decode(value.value())?));
            }
        }
        failed.sort_by_key(|(bind, seq, _)| (*bind, *seq));
        Ok(failed)
    }

    pub fn retry_failed(&self, bind: Uuid, seq: u64) -> Result<bool, DbError> {
        let key = buffer_key(bind, seq);
        let mut transaction = self.database.begin_write().map_err(redb_error)?;
        transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
        let failed = {
            let table = transaction.open_table(WEBHOOK_FAILED).map_err(redb_error)?;
            table.get(key.as_slice()).map_err(redb_error)?.map(|value| value.value().to_vec())
        };
        let Some(failed) = failed else {
            return Ok(false);
        };
        let failed: FailedWebhook = decode(&failed)?;
        {
            let request = encode(&failed.request)?;
            let mut active = transaction.open_table(WEBHOOK_BUFFER).map_err(redb_error)?;
            active.insert(key.as_slice(), request.as_slice()).map_err(redb_error)?;
            let mut failed_table = transaction.open_table(WEBHOOK_FAILED).map_err(redb_error)?;
            failed_table.remove(key.as_slice()).map_err(redb_error)?;
        }
        transaction.commit().map_err(redb_error)?;
        Ok(true)
    }

    pub fn delete_failed(&self, bind: Uuid, seq: u64) -> Result<bool, DbError> {
        self.delete_raw(WEBHOOK_FAILED, &buffer_key(bind, seq))
    }

    pub fn fail_buffered(&self, bind: Uuid, seq: u64, reason: &str) -> Result<(), DbError> {
        let key = buffer_key(bind, seq);
        let mut transaction = self.database.begin_write().map_err(redb_error)?;
        transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
        let request = {
            let table = transaction.open_table(WEBHOOK_BUFFER).map_err(redb_error)?;
            table.get(key.as_slice()).map_err(redb_error)?.map(|value| value.value().to_vec())
        }
        .ok_or_else(|| DbError::Data("buffered request not found".to_owned()))?;
        let failed = encode(&FailedWebhook {
            request: decode(&request)?,
            reason: reason.chars().take(512).collect(),
            failed_at: Timestamp::now(),
        })?;
        {
            let mut failed_table = transaction.open_table(WEBHOOK_FAILED).map_err(redb_error)?;
            failed_table.insert(key.as_slice(), failed.as_slice()).map_err(redb_error)?;
            let mut active = transaction.open_table(WEBHOOK_BUFFER).map_err(redb_error)?;
            active.remove(key.as_slice()).map_err(redb_error)?;
        }
        transaction.commit().map_err(redb_error)
    }

    pub(crate) fn count_raw(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        bind: Uuid,
    ) -> Result<u32, DbError> {
        let transaction = self.database.begin_read().map_err(redb_error)?;
        let table = transaction.open_table(definition).map_err(redb_error)?;
        let mut count = 0_u32;
        for entry in table.iter().map_err(redb_error)? {
            let (key, _) = entry.map_err(redb_error)?;
            if parse_buffer_key(key.value()).is_some_and(|(stored, _)| stored == bind) {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }
}
