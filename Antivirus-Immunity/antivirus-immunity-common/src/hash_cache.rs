//! Hash Cache — 跨平台 LRU 哈希缓存
//!
//! 生物学类比：补体系统调理素标记
//! 缓存已计算的 SHA256 哈希，避免对同一文件重复 IO。

use anyhow::Result;
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::num::NonZeroUsize;
use std::time::SystemTime;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    path: String,
    size: u64,
    modified: u64,
}

pub struct HashCache {
    cache: LruCache<CacheKey, String>,
    hits: u64,
    misses: u64,
}

impl HashCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1024).unwrap());
        Self {
            cache: LruCache::new(cap),
            hits: 0,
            misses: 0,
        }
    }

    pub fn get_or_compute(&mut self, path: &str) -> Result<String> {
        let key = self.make_key(path)?;
        if let Some(hash) = self.cache.get(&key) {
            self.hits += 1;
            return Ok(hash.clone());
        }
        self.misses += 1;
        let hash = Self::compute_sha256(path)?;
        self.cache.put(key, hash.clone());
        Ok(hash)
    }

    fn make_key(&self, path: &str) -> Result<CacheKey> {
        let metadata = fs::metadata(path)?;
        let size = metadata.len();
        let modified = metadata
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(CacheKey {
            path: path.to_string(),
            size,
            modified,
        })
    }

    fn compute_sha256(path: &str) -> Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    pub fn stats_summary(&self) -> String {
        format!(
            "HashCache: {} hits / {} misses ({:.1}% hit rate)",
            self.hits,
            self.misses,
            self.hit_ratio() * 100.0,
        )
    }
}
