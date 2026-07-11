//! Hash Cache — LRU 哈希缓存
//!
//! 生物学类比：补体系统的调理素 (Opsonin) 标记
//! 补体系统会在已识别的病原体表面标记调理素，
//! 下次遇到同一病原体时可以快速识别，无需重新分析。
//!
//! 本模块使用 LRU 缓存避免对同一可执行文件重复计算 SHA256，
//! 以 (路径, 文件大小, 修改时间) 作为缓存键。

use anyhow::Result;
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::num::NonZeroUsize;
use std::time::SystemTime;

/// Cache key bound to high-resolution file metadata.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    path: String,
    size: u64,
    modified_nanos: u128,
    created_nanos: u128,
}

pub struct HashCache {
    cache: LruCache<CacheKey, String>,
    hits: u64,
    misses: u64,
}

impl HashCache {
    /// Create a new cache with the given capacity
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1024).unwrap());
        Self {
            cache: LruCache::new(cap),
            hits: 0,
            misses: 0,
        }
    }

    /// Get or compute the SHA256 hash for a file.
    /// Opens the file before deriving the key and verifies metadata again after
    /// hashing so a replacement cannot pair an old key with new contents.
    pub fn get_or_compute(&mut self, path: &str) -> Result<String> {
        let mut file = File::open(path)?;
        let key = Self::make_key(path, &file.metadata()?);

        // Check cache
        if let Some(hash) = self.cache.get(&key) {
            self.hits += 1;
            return Ok(hash.clone());
        }

        // Cache miss — compute hash
        self.misses += 1;
        let hash = Self::compute_sha256(&mut file)?;
        let key_after = Self::make_key(path, &file.metadata()?);
        if key != key_after {
            return Err(anyhow::anyhow!(
                "File changed while hashing; refusing unstable digest: {}",
                path
            ));
        }
        self.cache.put(key, hash.clone());
        Ok(hash)
    }

    fn make_key(path: &str, metadata: &fs::Metadata) -> CacheKey {
        CacheKey {
            path: path.to_lowercase(), // Normalize case for Windows
            size: metadata.len(),
            modified_nanos: timestamp_nanos(metadata.modified()),
            created_nanos: timestamp_nanos(metadata.created()),
        }
    }

    /// Compute SHA256 of a file
    fn compute_sha256(file: &mut File) -> Result<String> {
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192]; // 8KB buffer

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }

        Ok(hex::encode(hasher.finalize()))
    }

    /// Get cache hit ratio for diagnostics
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    /// Get cache stats summary
    pub fn stats_summary(&self) -> String {
        format!(
            "Hash Cache: {} entries, {} hits / {} misses ({:.1}% hit rate)",
            self.cache.len(),
            self.hits,
            self.misses,
            self.hit_ratio() * 100.0
        )
    }
}

fn timestamp_nanos(value: std::io::Result<SystemTime>) -> u128 {
    value
        .unwrap_or(SystemTime::UNIX_EPOCH)
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn same_size_immediate_rewrite_invalidates_cached_hash() {
        let path = std::env::temp_dir().join(format!("immunity-hash-{}.bin", uuid::Uuid::new_v4()));
        fs::write(&path, b"AAAA").expect("write first content");
        let mut cache = HashCache::new(4);
        let first = cache
            .get_or_compute(path.to_str().expect("utf8 path"))
            .expect("first hash");

        let mut file = File::create(&path).expect("replace content");
        file.write_all(b"BBBB").expect("write replacement");
        file.sync_all().expect("flush replacement");
        let second = cache
            .get_or_compute(path.to_str().expect("utf8 path"))
            .expect("second hash");

        assert_ne!(first, second);
        let _ = fs::remove_file(path);
    }
}
