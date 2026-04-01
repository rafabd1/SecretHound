# Supported Secret Types

SecretHound currently loads its built-in patterns from:

- `core/patterns/default_patterns.yaml`

For the exact and current list in your runtime, use:

```bash
secrethound --list-patterns
```

You can also replace built-in patterns with your own YAML file:

```bash
secrethound --patterns-file ./my_patterns.yaml --list-patterns
```

## Detection Model

Secret detection combines:

- Regex matching by pattern type
- Context/heuristic filtering (code/doc/path/content-type noise)
- Pattern-level constraints (`minlength`, `maxlength`, keyword filters)
- Optional Shannon entropy validation (`useentropy`, `minentropy`, `entropyminlength`)

## Categories and Examples

### AWS
- `aws_access_key`
- `aws_secret_key`

### GCP
- `google_api_key`
- `google_cloud_platform`

### Azure
- `azure_connection_string`
- `azure_sql_connection`
- `azure_service_bus`
- `azure_cosmosdb`

### Cloud / SaaS
- `mailgun_api_key`
- `digitalocean_access_token`
- `digitalocean_oauth_token`
- `digitalocean_refresh_token`
- `cloudflare_api_token`
- `datadog_api_key`
- `shopify_access_token`
- `shopify_custom_app_token`
- `shopify_private_app_token`
- `shopify_shared_secret`
- `netlify_access_token`
- `mailchimp_api_key`
- `sendgrid_api_key`
- `sendinblue_api_key`
- `sentry_auth_token`
- `telegram_bot_token`
- `huggingface_api_token`
- `twilio_api_key`
- `mapbox_secret_token`

### Payment
- `stripe_secret_key`
- `stripe_publishable_key`
- `stripe_test_secret_key`
- `stripe_test_publishable_key`
- `stripe_restricted_key`
- `square_access_token`
- `square_oauth_secret`
- `paypal_client_id`
- `paypal_client_secret`
- `braintree_token`
- `credit_card_number`

### Auth
- `jwt_token`
- `bearer_token`
- `oauth_token`
- `oauth2_access_token`
- `auth_token`
- `session_token`
- `basic_auth` (disabled by default)

### Code / Dev Platforms
- `github_token`
- `github_personal_token`
- `github_fine_grained_token`
- `npm_access_token`
- `docker_hub_token`
- `slack_token`
- `slack_webhook`
- `discord_bot_token`
- `discord_webhook`
- `postman_api_key`

### CI/CD
- `gitlab_runner_token`
- `gitlab_personal_token`
- `jenkins_api_token`

### Database
- `mongodb_uri`
- `mongodb_srv_connection`
- `postgresql_connection_string`
- `mysql_connection_string`
- `redis_url`
- `msql_connection_string`

### Crypto / Keys
- `private_key_content`
- `private_key_var`
- `encryption_key`
- `signing_key`

### Generic / Config
- `api_key_assignment`
- `config_api_key`
- `config_secret`
- `generic_password` (disabled by default)

### LLM Providers
- `llm_openai_api_key`
- `llm_anthropic_api_key`
- `llm_groq_api_key`
- `llm_openrouter_api_key`
- `llm_perplexity_api_key`
- `llm_replicate_api_token`
- `llm_xai_grok_api_key`
- `llm_kimi_moonshot_api_key`
- `llm_qwen_dashscope_api_key`
- `llm_zhipu_glm_api_key`
- `llm_doubao_ark_api_key`

### Bash
- `bash_command_suspicious`

### Imported Providers
- Hundreds of additional service-scoped provider patterns imported from `secrets-patterns-db` are included directly by provider name (for example, `neutrinoapi_1`, `customerio`, `zipcodeapi`) and are categorized under existing categories (mainly `cloud`).

### PII
- `email_address`
- `phone_number`
- `ipv4_address`
- `ipv6_address`
- `mac_address`
- `us_zip_code`
- `serial_number`

### Web3
- `ethereum_address`
- `web3_private_key`
- `web3_provider_key`

### URL (disabled by default)
- `url_generic`
- `url_path`
- `generic_domain_name`

## Notes

- Some patterns are intentionally disabled by default and can still be loaded by category include flags.
- `pii` patterns are disabled by default; enable them explicitly with `--include-categories pii` (or include `pii` alongside other categories).
- Pattern behavior is defined by YAML fields (`enabled`, lengths, keyword constraints, entropy fields), allowing maintenance without changing Go code.

