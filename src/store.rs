// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! People and their native credentials. The private subject never leaves AIS:
//! clients only ever see a pairwise digest of it.

use std::str::FromStr as _;

use nilxone_contracts::{PubDress, PubDressLabel};
use sqlx::{
    Row as _, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

/// The sixteen prefixes, `0x0`–`0xf`.
pub const DISCRIMINATORS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS identities (
    subject BLOB PRIMARY KEY NOT NULL CHECK (length(subject) = 32),
    pub_dress TEXT NOT NULL UNIQUE COLLATE BINARY,
    -- The canonical (UTS-46) DNS label of the address. Unique, so two
    -- addresses that read alike cannot both be taken, and every lookup goes
    -- through it, so a person finds their address however they type its case.
    label TEXT NOT NULL UNIQUE COLLATE NOCASE,
    prefix_assigned INTEGER NOT NULL CHECK (prefix_assigned IN (0, 1)),
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0)
) STRICT;
";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("storage failed: {0}")]
    Storage(#[from] sqlx::Error),
    #[error("no entropy")]
    Entropy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub subject: [u8; 32],
    pub pub_dress: String,
    pub password_hash: String,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Registration {
    Registered(Identity),
    /// The address, or one that reads alike, is already someone's.
    Taken,
    /// The address cannot be represented as a public label.
    Unrepresentable,
}

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str(url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(if url.contains(":memory:") { 1 } else { 5 })
            .connect_with(options)
            .await?;
        sqlx::raw_sql(SCHEMA).execute(&pool).await?;
        Ok(Self { pool })
    }

    /// The address that reads like this one, as it was registered.
    pub async fn find(&self, pub_dress: &PubDress) -> Result<Option<Identity>, StoreError> {
        let Ok(label) = PubDressLabel::stem(pub_dress) else {
            return Ok(None);
        };
        let row =
            sqlx::query("SELECT subject, pub_dress, password_hash FROM identities WHERE label = ?")
                .bind(label.as_str())
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(identity))
    }

    /// Every address that reads like `0x?{slug}`, whatever its prefix.
    pub async fn find_by_slug(&self, slug: &str) -> Result<Vec<Identity>, StoreError> {
        let labels: Vec<String> = DISCRIMINATORS
            .iter()
            .filter_map(|discriminator| {
                let address = PubDress::from_str(&format!("0x{discriminator}{slug}")).ok()?;
                PubDressLabel::stem(&address)
                    .ok()
                    .map(|label| label.as_str().to_owned())
            })
            .collect();
        if labels.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = vec!["?"; labels.len()].join(", ");
        let sql = format!(
            "SELECT subject, pub_dress, password_hash FROM identities \
             WHERE label IN ({placeholders}) ORDER BY pub_dress"
        );
        let mut query = sqlx::query(&sql);
        for label in &labels {
            query = query.bind(label);
        }
        let rows = query.fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(identity).collect())
    }

    /// Whether the address, or one that reads alike, is free. Advisory only:
    /// `register` is the collision boundary.
    pub async fn is_free(&self, pub_dress: &PubDress) -> Result<bool, StoreError> {
        let Ok(label) = PubDressLabel::stem(pub_dress) else {
            return Ok(false);
        };
        let taken: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM identities WHERE label = ?)")
                .bind(label.as_str())
                .fetch_one(&self.pool)
                .await?;
        Ok(!taken)
    }

    /// A free address for this slug with a prefix AIS chooses, for products
    /// that never show the prefix. The order is random, so the prefix says
    /// nothing about when the person arrived.
    pub async fn free_prefix_for(&self, slug: &str) -> Result<Option<PubDress>, StoreError> {
        let mut order = DISCRIMINATORS;
        let entropy = crate::crypto::random_bytes::<16>().ok_or(StoreError::Entropy)?;
        for index in (1..order.len()).rev() {
            order.swap(index, usize::from(entropy[index]) % (index + 1));
        }
        for discriminator in order {
            let Ok(candidate) = PubDress::from_str(&format!("0x{discriminator}{slug}")) else {
                return Ok(None);
            };
            if self.is_free(&candidate).await? {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    pub async fn register(
        &self,
        pub_dress: &PubDress,
        prefix_assigned: bool,
        password_hash: &str,
        now: u64,
    ) -> Result<Registration, StoreError> {
        let Ok(label) = PubDressLabel::stem(pub_dress) else {
            return Ok(Registration::Unrepresentable);
        };
        let subject = crate::crypto::random_bytes::<32>().ok_or(StoreError::Entropy)?;
        let created_at = i64::try_from(now).unwrap_or(i64::MAX);
        let result = sqlx::query(
            "INSERT INTO identities (subject, pub_dress, label, prefix_assigned, password_hash, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(subject.as_slice())
        .bind(pub_dress.as_str())
        .bind(label.as_str())
        .bind(i64::from(prefix_assigned))
        .bind(password_hash)
        .bind(created_at)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(Registration::Registered(Identity {
                subject,
                pub_dress: pub_dress.as_str().to_owned(),
                password_hash: password_hash.to_owned(),
            })),
            // The unique constraints are the collision boundary: a check
            // before the insert can always lose a race.
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                Ok(Registration::Taken)
            }
            Err(error) => Err(error.into()),
        }
    }
}

fn identity(row: sqlx::sqlite::SqliteRow) -> Identity {
    let subject: Vec<u8> = row.get("subject");
    Identity {
        subject: subject
            .try_into()
            .expect("the schema keeps subjects at 32 bytes"),
        pub_dress: row.get("pub_dress"),
        password_hash: row.get("password_hash"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(value: &str) -> PubDress {
        PubDress::from_str(value).unwrap()
    }

    #[tokio::test]
    async fn registers_once_and_finds_by_address_and_slug() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let sky = address("0x0sky");
        assert!(store.is_free(&sky).await.unwrap());
        let Registration::Registered(identity) =
            store.register(&sky, false, "hash", 1).await.unwrap()
        else {
            panic!("registers")
        };
        assert_eq!(store.find(&sky).await.unwrap(), Some(identity.clone()));
        assert_eq!(
            store.register(&sky, false, "hash", 2).await.unwrap(),
            Registration::Taken
        );
        assert!(!store.is_free(&sky).await.unwrap());
        store
            .register(&address("0x1sky"), true, "hash", 3)
            .await
            .unwrap();
        let both = store.find_by_slug("sky").await.unwrap();
        assert_eq!(both.len(), 2);
        assert_ne!(both[0].subject, both[1].subject);
    }

    #[tokio::test]
    async fn an_address_that_reads_alike_is_taken() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        store
            .register(&address("0x0Sky"), false, "hash", 1)
            .await
            .unwrap();
        let alike = address("0x0sky");
        assert!(!store.is_free(&alike).await.unwrap());
        // However it is typed, the person finds the address they registered.
        let found = store.find(&alike).await.unwrap().expect("found alike");
        assert_eq!(found.pub_dress, "0x0Sky");
        let by_slug = store.find_by_slug("SKY").await.unwrap();
        assert_eq!(by_slug, vec![found]);
        assert_eq!(
            store.register(&alike, false, "hash", 2).await.unwrap(),
            Registration::Taken
        );
    }

    #[tokio::test]
    async fn assigns_a_free_prefix_until_none_is_left() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            let candidate = store
                .free_prefix_for("sky")
                .await
                .unwrap()
                .expect("a free prefix");
            assert_eq!(candidate.slug(), "sky");
            assert!(seen.insert(candidate.discriminator()));
            store.register(&candidate, true, "hash", 1).await.unwrap();
        }
        assert_eq!(store.free_prefix_for("sky").await.unwrap(), None);
    }
}
