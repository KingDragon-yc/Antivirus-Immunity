//! AI Cortex — 本地 AI 决策中枢
//!
//! 生物学类比：大脑皮层 (Cerebral Cortex)
//! 生物的免疫系统虽然大部分是自主运作的，但大脑皮层能进行高级的
//! 模式识别和决策。AI Cortex 模块模拟了这个角色——当免疫引擎的
//! 规则系统无法做出明确判断时，将上下文信息交给本地 AI 模型进行
//! "深度思考"。
//!
//! 设计原则：
//! - 本地优先：默认使用 Ollama 运行本地模型，无需上传敏感数据
//! - 优雅降级：AI 不可用时回退到规则引擎判断
//! - 非阻塞：AI 查询异步执行，不阻塞主监控循环
//! - 可审计：所有 AI 判断都附带推理过程，可被人类审核

use serde::{Deserialize, Serialize};

/// AI model backend configuration
#[derive(Debug, Clone)]
pub struct AiCortexConfig {
    /// Ollama API endpoint (default: localhost:11434)
    pub endpoint: String,
    /// Model name (e.g., "llama3.2:1b", "qwen2.5:3b", "phi3:mini")
    pub model: String,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Whether AI cortex is enabled
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

/// The verdict returned by the AI Cortex
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVerdict {
    /// SAFE, SUSPICIOUS, MALICIOUS, or UNCERTAIN
    pub classification: String,
    /// Confidence level 0.0 ~ 1.0
    pub confidence: f64,
    /// The AI's reasoning chain (for human audit)
    pub reasoning: String,
    /// Recommended action
    pub recommendation: String,
}

/// Request payload for Ollama generate API
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

/// Response from Ollama generate API
#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

/// Process context information passed to the AI for analysis
#[derive(Debug, Clone, Serialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub hash: Option<String>,
    pub path_verdict: String,
    pub yara_matches: Vec<String>,
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
            available: false, // Will be tested on first use
        }
    }

    /// Check if Ollama is running and the model is available
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
                    println!("[+] AI Cortex: Using model '{}'", self.config.model);
                } else {
                    println!("[!] AI Cortex: Ollama responded with error. AI features disabled.");
                }
                self.available
            }
            Err(_) => {
                self.available = false;
                println!(
                    "[!] AI Cortex: Cannot reach Ollama at {}. AI features disabled.",
                    self.config.endpoint
                );
                println!("[*] AI Cortex: Falling back to rule-based evaluation.");
                println!(
                    "[*] Hint: Install Ollama (https://ollama.ai) and run 'ollama pull {}'",
                    self.config.model
                );
                false
            }
        }
    }

    /// Ask the AI to evaluate a suspicious process.
    /// This is the "deep thinking" path — only invoked for ambiguous cases.
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
                temperature: 0.1, // Low temperature for consistent security analysis
                num_predict: 512,
            },
        };

        let url = format!("{}/api/generate", self.config.endpoint);

        match self.client.post(&url).json(&request).send().await {
            Ok(resp) => {
                if let Ok(ollama_resp) = resp.json::<OllamaResponse>().await {
                    return self.parse_verdict(&ollama_resp.response);
                }
                None
            }
            Err(e) => {
                eprintln!("[!] AI Cortex: Request failed: {}", e);
                None
            }
        }
    }

    /// Build the analysis prompt with structured context
    fn build_prompt(&self, ctx: &ProcessContext) -> String {
        format!(
            r#"You are a cybersecurity analyst AI embedded in an antivirus system.
Analyze the following process and determine if it is safe, suspicious, or malicious.

## Process Information
- **PID**: {}
- **Name**: {}
- **Path**: {}
- **SHA256 Hash**: {}
- **Path Validation**: {}
- **YARA Matches**: {}
- **System Danger Level**: {}
- **Hash in Trusted DB**: {}

## Instructions
1. Analyze all available signals together.
2. Consider if the process name/path combination is legitimate.
3. Check for common malware behaviors (impersonation, suspicious locations, etc.).
4. Provide your assessment.

## Required Output Format (STRICT JSON, no markdown):
{{"classification": "SAFE|SUSPICIOUS|MALICIOUS|UNCERTAIN", "confidence": 0.0-1.0, "reasoning": "your analysis", "recommendation": "ALLOW|MONITOR|QUARANTINE|TERMINATE"}}
"#,
            ctx.pid,
            ctx.name,
            ctx.path.as_deref().unwrap_or("UNKNOWN"),
            ctx.hash.as_deref().unwrap_or("UNAVAILABLE"),
            ctx.path_verdict,
            if ctx.yara_matches.is_empty() {
                "None".to_string()
            } else {
                ctx.yara_matches.join(", ")
            },
            ctx.danger_level,
            if ctx.is_known_hash {
                "Yes (Trusted)"
            } else {
                "No (Unknown)"
            },
        )
    }

    /// Parse the AI's response into a structured verdict
    fn parse_verdict(&self, response: &str) -> Option<AiVerdict> {
        // Try to extract JSON from the response
        let trimmed = response.trim();

        // Try direct parse first
        if let Ok(verdict) = serde_json::from_str::<AiVerdict>(trimmed) {
            return Some(verdict);
        }

        // Try to find JSON within the response (AI sometimes wraps in markdown)
        if let Some(start) = trimmed.find('{') {
            if let Some(end) = trimmed.rfind('}') {
                let json_str = &trimmed[start..=end];
                if let Ok(verdict) = serde_json::from_str::<AiVerdict>(json_str) {
                    return Some(verdict);
                }
            }
        }

        // Fallback: construct verdict from keywords
        let lower = trimmed.to_lowercase();
        let classification = if lower.contains("malicious") || lower.contains("malware") {
            "MALICIOUS"
        } else if lower.contains("suspicious") {
            "SUSPICIOUS"
        } else if lower.contains("safe") || lower.contains("benign") || lower.contains("legitimate")
        {
            "SAFE"
        } else {
            "UNCERTAIN"
        };

        Some(AiVerdict {
            classification: classification.to_string(),
            confidence: 0.5,
            reasoning: format!(
                "(Parsed from unstructured response) {}",
                &trimmed[..trimmed.len().min(300)]
            ),
            recommendation: match classification {
                "MALICIOUS" => "TERMINATE".to_string(),
                "SUSPICIOUS" => "MONITOR".to_string(),
                _ => "ALLOW".to_string(),
            },
        })
    }

    /// Check if AI cortex is currently available
    pub fn is_available(&self) -> bool {
        self.available
    }
}
