//! AI Cortex — 本地 AI 决策中枢 (跨平台)
//!
//! 生物学类比：大脑皮层 (Cerebral Cortex)
//! 对模糊案例调用本地 Ollama LLM 进行深度分析。
//!
//! 设计原则：
//! - 本地优先：Ollama 运行本地模型，无需上传敏感数据
//! - 优雅降级：AI 不可用时回退到规则引擎
//! - 非阻塞：异步 HTTP 请求
//! - 可审计：所有判断附带推理链

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AiCortexConfig {
    pub endpoint: String,
    pub model: String,
    pub timeout_secs: u64,
    pub enabled: bool,
}

impl Default for AiCortexConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:11434".to_string(),
            model: "qwen2.5:3b".to_string(),
            timeout_secs: 30,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVerdict {
    pub classification: String,
    pub confidence: f64,
    pub reasoning: String,
    pub recommendation: String,
}

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Serialize)]
struct OllamaOptions {
    temperature: f64,
    num_predict: i32,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

/// 进程上下文 — 传递给 AI 的分析素材
#[derive(Debug, Clone, Serialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub hash: Option<String>,
    pub cmdline: Option<String>,
    pub container_id: Option<String>,
    pub parent_chain: Vec<String>,
    pub network_activity: Vec<String>,
    pub file_access: Vec<String>,
    pub danger_level: String,
    pub is_known_hash: bool,
}

pub struct AiCortex {
    config: AiCortexConfig,
    client: reqwest::Client,
    available: bool,
}

impl AiCortex {
    pub fn new(config: AiCortexConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .unwrap_or_default();
        Self {
            config,
            client,
            available: false,
        }
    }

    pub async fn health_check(&mut self) -> bool {
        if !self.config.enabled {
            self.available = false;
            return false;
        }
        let url = format!("{}/api/tags", self.config.endpoint);
        match self.client.get(&url).send().await {
            Ok(resp) => {
                self.available = resp.status().is_success();
                if self.available {
                    println!(
                        "[+] AI Cortex: Connected to Ollama at {}",
                        self.config.endpoint
                    );
                    println!("[+] AI Cortex: Model '{}'", self.config.model);
                } else {
                    println!("[!] AI Cortex: Ollama error. AI disabled.");
                }
                self.available
            }
            Err(_) => {
                self.available = false;
                println!(
                    "[!] AI Cortex: Cannot reach Ollama at {}. Falling back to rules.",
                    self.config.endpoint
                );
                false
            }
        }
    }

    pub async fn evaluate(&self, context: &ProcessContext) -> Option<AiVerdict> {
        if !self.available || !self.config.enabled {
            return None;
        }

        let prompt = self.build_prompt(context);
        let request = OllamaRequest {
            model: self.config.model.clone(),
            prompt,
            stream: false,
            options: OllamaOptions {
                temperature: 0.1,
                num_predict: 512,
            },
        };

        let url = format!("{}/api/generate", self.config.endpoint);
        match self.client.post(&url).json(&request).send().await {
            Ok(resp) => {
                if let Ok(r) = resp.json::<OllamaResponse>().await {
                    return self.parse_verdict(&r.response);
                }
                None
            }
            Err(e) => {
                eprintln!("[!] AI Cortex: {}", e);
                None
            }
        }
    }

    fn build_prompt(&self, ctx: &ProcessContext) -> String {
        format!(
            r#"You are a cybersecurity analyst AI embedded in a Linux cloud-native security system (eBPF-based).
Analyze the following process and determine if it is safe, suspicious, or malicious.

## Process Information
- **PID**: {}
- **Name**: {}
- **Path**: {}
- **SHA256 Hash**: {}
- **Cmdline**: {}
- **Container**: {}
- **Parent Chain**: {}
- **Network Activity**: {}
- **File Access**: {}
- **Danger Level**: {}
- **Known Hash**: {}

## Context
This system runs on cloud Linux servers protecting Docker containers and AI Agent sandboxes.
Consider:
1. Is this a legitimate cloud workload (nginx, mysql, python, node, etc.)?
2. Does the process-parent chain look normal (e.g., dockerd → containerd → shim → app)?
3. Is there suspicious network activity (reverse shell, mining pool connections)?
4. Any sensitive file access (/etc/shadow, ~/.ssh, /var/run/docker.sock)?
5. For AI Agent processes: autonomous code execution is expected but boundary violations are not.

## Required Output (STRICT JSON):
{{"classification": "SAFE|SUSPICIOUS|MALICIOUS|UNCERTAIN", "confidence": 0.0-1.0, "reasoning": "your analysis", "recommendation": "ALLOW|MONITOR|BLOCK|TERMINATE"}}
"#,
            ctx.pid,
            ctx.name,
            ctx.path.as_deref().unwrap_or("UNKNOWN"),
            ctx.hash.as_deref().unwrap_or("N/A"),
            ctx.cmdline.as_deref().unwrap_or("N/A"),
            ctx.container_id.as_deref().unwrap_or("HOST"),
            if ctx.parent_chain.is_empty() {
                "N/A".to_string()
            } else {
                ctx.parent_chain.join(" → ")
            },
            if ctx.network_activity.is_empty() {
                "None".to_string()
            } else {
                ctx.network_activity.join("; ")
            },
            if ctx.file_access.is_empty() {
                "None".to_string()
            } else {
                ctx.file_access.join("; ")
            },
            ctx.danger_level,
            if ctx.is_known_hash { "Yes" } else { "No" },
        )
    }

    fn parse_verdict(&self, response: &str) -> Option<AiVerdict> {
        let trimmed = response.trim();

        // Direct JSON parse
        if let Ok(v) = serde_json::from_str::<AiVerdict>(trimmed) {
            return Some(v);
        }

        // Extract JSON from markdown wrapping
        if let Some(start) = trimmed.find('{') {
            if let Some(end) = trimmed.rfind('}') {
                if let Ok(v) = serde_json::from_str::<AiVerdict>(&trimmed[start..=end]) {
                    return Some(v);
                }
            }
        }

        // Keyword fallback
        let lower = trimmed.to_lowercase();
        let classification = if lower.contains("malicious") || lower.contains("malware") {
            "MALICIOUS"
        } else if lower.contains("suspicious") {
            "SUSPICIOUS"
        } else if lower.contains("safe") || lower.contains("benign") {
            "SAFE"
        } else {
            "UNCERTAIN"
        };

        Some(AiVerdict {
            classification: classification.to_string(),
            confidence: 0.5,
            reasoning: format!("(Unstructured) {}", &trimmed[..trimmed.len().min(300)]),
            recommendation: match classification {
                "MALICIOUS" => "TERMINATE".to_string(),
                "SUSPICIOUS" => "MONITOR".to_string(),
                _ => "ALLOW".to_string(),
            },
        })
    }

    pub fn is_available(&self) -> bool {
        self.available
    }
}
