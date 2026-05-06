use crate::models::{ReportPlatform, Severity};
use anyhow::{Result, anyhow, Context};
use reqwest::Client;
use serde_json::json;
use base64::{Engine as _, engine::general_purpose};

pub struct PlatformClient {
    client: Client,
    platform: ReportPlatform,
    api_key: String,
    username: Option<String>, // Required for H1 (Basic auth)
}

impl PlatformClient {
    pub fn new(platform: ReportPlatform, api_key: String, username: Option<String>) -> Self {
        Self {
            client: Client::new(),
            platform,
            api_key,
            username,
        }
    }

    pub async fn submit(
        &self,
        report_md: &str,
        title: &str,
        severity: &Severity,
        program_handle: &str,
    ) -> Result<String> {
        match self.platform {
            ReportPlatform::HackerOne => self.submit_h1(report_md, title, severity, program_handle).await,
            ReportPlatform::BugCrowd => self.submit_bugcrowd(report_md, title, severity, program_handle).await,
            ReportPlatform::Intigriti => self.submit_intigriti(report_md, title, severity, program_handle).await,
        }
    }

    async fn submit_h1(
        &self,
        report_md: &str,
        title: &str,
        severity: &Severity,
        program_handle: &str,
    ) -> Result<String> {
        let username = self.username.as_ref().ok_or_else(|| anyhow!("H1_USERNAME is required for HackerOne submissions"))?;
        let auth = general_purpose::STANDARD.encode(format!("{}:{}", username, self.api_key));

        let payload = json!({
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": program_handle,
                    "title": title,
                    "vulnerability_information": report_md,
                    "severity_rating": self.platform.severity_label(severity),
                }
            }
        });

        let resp = self.client
            .post("https://api.hackerone.com/v1/reports")
            .header("Authorization", format!("Basic {}", auth))
            .json(&payload)
            .send()
            .await
            .context("Failed to send request to HackerOne API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("HackerOne API error: {} - {}", status, err_text));
        }

        let body: serde_json::Value = resp.json().await?;
        let report_id = body["data"]["id"].as_str().ok_or_else(|| anyhow!("Failed to parse report ID from H1 response"))?;
        
        Ok(format!("https://hackerone.com/reports/{}", report_id))
    }

    async fn submit_bugcrowd(
        &self,
        report_md: &str,
        title: &str,
        severity: &Severity,
        program_handle: &str,
    ) -> Result<String> {
        // Bugcrowd External Submission API (requires Token auth)
        // Note: program_handle is used as the target or part of the URL/payload depending on API version.
        // This implementation follows the user's spec: Authorization: Token token={key}
        
        let payload = json!({
            "submission": {
                "title": title,
                "vulnerability_description": report_md,
                "severity": self.platform.severity_label(severity),
                "program_handle": program_handle,
            }
        });

        let resp = self.client
            .post("https://tracker.bugcrowd.com/external_submissions.json")
            .header("Authorization", format!("Token token={}", self.api_key))
            .json(&payload)
            .send()
            .await
            .context("Failed to send request to Bugcrowd API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Bugcrowd API error: {} - {}", status, err_text));
        }

        // Bugcrowd usually returns a 201 Created with the submission details
        Ok("Submission successful (check Bugcrowd dashboard)".to_string())
    }

    async fn submit_intigriti(
        &self,
        report_md: &str,
        title: &str,
        severity: &Severity,
        program_handle: &str,
    ) -> Result<String> {
        let payload = json!({
            "title": title,
            "description": report_md,
            "severityId": match severity {
                Severity::Critical => 4,
                Severity::High => 3,
                Severity::Medium => 2,
                Severity::Low => 1,
                Severity::Info => 0,
            },
            "programHandle": program_handle,
        });

        let resp = self.client
            .post("https://api.intigriti.com/external/researcher/v1/submission")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&payload)
            .send()
            .await
            .context("Failed to send request to Intigriti API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Intigriti API error: {} - {}", status, err_text));
        }

        Ok("Submission successful (check Intigriti dashboard)".to_string())
    }
}
