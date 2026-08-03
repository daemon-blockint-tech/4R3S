use anyhow::Result;
use ares_core::{AresConfig, LlmProvider};
use dialoguer::{theme::ColorfulTheme, Input, Password, Select};
use std::path::PathBuf;

fn normalize_endpoint(url: String, provider: &LlmProvider) -> String {
    let trimmed = url.trim_end_matches('/');
    match provider {
        LlmProvider::Openai | LlmProvider::Ollama => {
            if !trimmed.ends_with("/chat/completions") {
                format!("{}/chat/completions", trimmed)
            } else {
                trimmed.to_string()
            }
        }
        LlmProvider::Anthropic => {
            if !trimmed.ends_with("/messages") {
                // Heuristic: if they just provided https://api.anthropic.com or similar
                if trimmed.ends_with("/v1") {
                    format!("{}/messages", trimmed)
                } else {
                    format!("{}/v1/messages", trimmed)
                }
            } else {
                trimmed.to_string()
            }
        }
        LlmProvider::Disabled => url,
    }
}

pub async fn setup(
    provider: Option<String>,
    api_key: Option<String>,
    model: Option<String>,
    endpoint: Option<String>,
    config_path: &PathBuf,
) -> Result<()> {
    // Load existing config or create new
    let mut config = if config_path.exists() {
        let content = tokio::fs::read_to_string(config_path).await?;
        toml::from_str(&content).unwrap_or_default()
    } else {
        AresConfig::default()
    };

    println!("=========================================");
    println!("ARES V3 LLM Setup");
    println!("=========================================");

    // 1. Provider
    let theme = ColorfulTheme::default();
    if let Some(p) = provider {
        config.llm_provider = match p.to_lowercase().as_str() {
            "openai" => LlmProvider::Openai,
            "anthropic" => LlmProvider::Anthropic,
            "ollama" => LlmProvider::Ollama,
            _ => {
                println!("Unknown provider '{}'. Using Openai as default.", p);
                LlmProvider::Openai
            }
        };
    } else {
        let providers = &["OpenAI", "Anthropic", "Ollama (Local)"];
        let default_idx = match config.llm_provider {
            LlmProvider::Openai => 0,
            LlmProvider::Anthropic => 1,
            LlmProvider::Ollama => 2,
            LlmProvider::Disabled => 0,
        };

        let selection = Select::with_theme(&theme)
            .with_prompt("Select LLM Provider")
            .items(providers)
            .default(default_idx)
            .interact()?;

        config.llm_provider = match selection {
            0 => LlmProvider::Openai,
            1 => LlmProvider::Anthropic,
            2 => LlmProvider::Ollama,
            _ => unreachable!(),
        };
    }

    // 2. Base URL
    if let Some(e) = endpoint {
        config.llm_base_url = Some(normalize_endpoint(e, &config.llm_provider));
    } else {
        let default_url = match config.llm_provider {
            LlmProvider::Openai => "https://api.openai.com/v1",
            LlmProvider::Anthropic => "https://api.anthropic.com/v1/messages",
            LlmProvider::Ollama => "http://localhost:11434/v1",
            LlmProvider::Disabled => "",
        };
        let current_url = config
            .llm_base_url
            .unwrap_or_else(|| default_url.to_string());

        // Strip the suffix for the prompt to keep it clean for the user
        let display_url = current_url
            .strip_suffix("/chat/completions")
            .unwrap_or(&current_url)
            .to_string();

        let url: String = Input::with_theme(&theme)
            .with_prompt("API Base URL")
            .default(display_url)
            .interact_text()?;

        config.llm_base_url = Some(normalize_endpoint(url, &config.llm_provider));
    }

    // 3. Model
    if let Some(m) = model {
        config.llm_model = m;
    } else {
        let default_model = match config.llm_provider {
            LlmProvider::Openai => "gpt-4-turbo",
            LlmProvider::Anthropic => "claude-3-5-sonnet-20240620",
            LlmProvider::Ollama => "llama3",
            LlmProvider::Disabled => "unknown",
        };

        let current_model =
            if config.llm_model == "claude-3-5-sonnet" || config.llm_model.is_empty() {
                default_model.to_string()
            } else {
                config.llm_model.clone()
            };

        let new_model: String = Input::with_theme(&theme)
            .with_prompt("Model Name")
            .default(current_model)
            .interact_text()?;

        config.llm_model = new_model;
    }

    // 4. API Key
    if let Some(k) = api_key {
        config.llm_api_key = Some(k);
    } else if config.llm_provider != LlmProvider::Ollama {
        let has_key = config.llm_api_key.is_some() || std::env::var("ARES_LLM_API_KEY").is_ok();
        let prompt_text = if has_key {
            "API Key (leave empty to keep current/env key)"
        } else {
            "API Key"
        };

        let key = Password::with_theme(&theme)
            .with_prompt(prompt_text)
            .allow_empty_password(has_key)
            .interact()?;

        if !key.is_empty() {
            config.llm_api_key = Some(key);
        }
    }

    // Save back to file
    let toml_str = toml::to_string_pretty(&config)?;
    tokio::fs::write(config_path, toml_str).await?;

    println!(
        "\n✓ LLM configuration saved successfully to {:?}",
        config_path
    );
    println!("  Provider : {:?}", config.llm_provider);
    println!("  Model    : {}", config.llm_model);
    if let Some(ep) = &config.llm_base_url {
        println!("  Endpoint : {}", ep);
    }

    Ok(())
}

pub async fn status(config: &AresConfig) -> Result<()> {
    println!("=========================================");
    println!("ARES V3 LLM Status");
    println!("=========================================");
    println!("Provider: {:?}", config.llm_provider);
    println!("Model: {}", config.llm_model);

    match &config.llm_api_key {
        Some(_) => {
            println!("API Key: Set (****)");
        }
        None => {
            let env_key = std::env::var("ARES_LLM_API_KEY").unwrap_or_default();
            if !env_key.is_empty() {
                println!("API Key: Set via ARES_LLM_API_KEY environment variable");
            } else {
                println!("API Key: Not configured");
            }
        }
    }

    if let Some(ep) = &config.llm_base_url {
        println!("Endpoint: {}", ep);
    } else {
        let env_ep = std::env::var("ARES_LLM_ENDPOINT")
            .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());
        println!("Endpoint: {} (default/env)", env_ep);
    }

    println!("=========================================");
    println!("To update: ares llm setup");

    Ok(())
}
