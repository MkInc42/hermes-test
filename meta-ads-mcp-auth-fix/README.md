# Meta Ads MCP Authentication Compatibility Fix

## Root Cause

The Meta Ads MCP server (`https://mcp.facebook.com/ads`) uses Streamable HTTP transport
with specific protocol requirements that neither `mcp-remote` nor Hermes' native HTTP MCP
client handle correctly:

1. **`mcp-remote`** sends a malformed `meta` field in JSON-RPC requests that Meta rejects:
   `"meta" for Request must be an dict or null.`

2. **Hermes native HTTP (`mcp.StreamableHTTP`)** fails during `ClientSession.initialize()`
   with `MCPError(-32603)`.

3. **Raw HTTP works fine** — POST with `Authorization: Bearer <token>`,
   `Content-Type: application/json`, `Accept: application/json, text/event-stream`
   returns a valid SSE response with session management via `mcp-session-id` header.

## Solution: Custom Python stdio-to-HTTP Bridge

A lightweight Python bridge (`meta_ads_bridge.py`) that:

- Reads JSON-RPC messages from stdin (standard MCP stdio protocol)
- POSTs them to `https://mcp.facebook.com/ads` with Bearer token auth
- Handles SSE streaming response parsing
- Manages the `mcp-session-id` header across calls
- **Strips `_meta` from params** — Meta rejects this field even when it's a valid dict
- Reads `META_ADS_MCP_ACCESS_TOKEN` from environment (with fallback to `.env` file)

## Status

- **`hermes mcp test meta-ads`**: SUCCEEDED (connected in 1.5s, 106 tools discovered)
- **Token**: Uses existing `META_ADS_MCP_ACCESS_TOKEN` from `~/.hermes/.env`
- **Server currently disabled** (`enabled: false`) — enable only when ready

## Required Gateway Restart

A gateway/session restart IS needed for the new `meta-ads` MCP server to be loaded by
running agent sessions. The `hermes mcp test` successfully validated the bridge, but
the tools won't appear in the agent toolset until a reconnect/reload happens.

## Config Changeset

### Global config (`~/.hermes/config.yaml`)

Replace the existing `meta-ads:` section (lines 782-861) with:

```yaml
meta-ads:
    command: /usr/bin/python3
    args:
    - /home/black/meta-ads-mcp-auth-fix/meta_ads_bridge.py
    env:
      META_ADS_MCP_ACCESS_TOKEN: ${META_ADS_MCP_ACCESS_TOKEN}
    connect_timeout: 60
    timeout: 180
    enabled: false
    sampling:
      enabled: false
    tools:
      include:
      - ads_account_get_activity_logs
      - ads_catalog_event_source_get
      - ads_catalog_event_source_get_catalogs
      - ads_catalog_event_source_get_health
      - ads_catalog_event_source_get_recommendations
      - ads_catalog_get_businesses
      - ads_catalog_get_catalogs
      - ads_catalog_get_data_sources
      - ads_catalog_get_details
      - ads_catalog_get_diagnostics
      - ads_catalog_get_dynamic_ads_health
      - ads_catalog_get_feed_rules
      - ads_catalog_get_product_details
      - ads_catalog_get_product_feed_details
      - ads_catalog_get_product_feed_upload_sessions
      - ads_catalog_get_product_product_sets
      - ads_catalog_get_product_set_details
      - ads_catalog_get_product_set_products
      - ads_catalog_get_product_sets
      - ads_catalog_list_catalogs
      - ads_catalog_list_partner_integrations
      - ads_catalog_list_product_feeds
      - ads_catalog_list_product_sets
      - ads_catalog_list_products
      - ads_catalog_search_product
      - ads_experiment_abtest_get_test
      - ads_experiment_check_eligibility
      - ads_experiment_lift_get_test
      - ads_experiment_list_tests
      - ads_get_ad_account_custom_audiences
      - ads_get_ad_account_pages
      - ads_get_ad_accounts
      - ads_get_ad_entities
      - ads_get_ad_images
      - ads_get_ad_preview
      - ads_get_ad_videos
      - ads_get_creative_ads
      - ads_get_creatives
      - ads_get_custom_audience
      - ads_get_custom_audience_adsets
      - ads_get_customconversions
      - ads_get_dataset_details
      - ads_get_dataset_quality
      - ads_get_dataset_stats
      - ads_get_datasets
      - ads_get_errors
      - ads_get_field_context
      - ads_get_help_article
      - ads_get_ig_accounts
      - ads_get_ig_media
      - ads_get_opportunity_score
      - ads_get_pages_for_business
      - ads_get_user_pages
      - ads_insights_advertiser_context
      - ads_insights_anomaly_signal
      - ads_insights_auction_ranking_benchmarks
      - ads_insights_industry_benchmark
      - ads_insights_performance_trend
      - ads_library_search
      - ads_pixel_event_read
      - ads_pixel_parameter_read
```

Dev-python profile config already has this change applied.

### To enable (when ready)

1. Set `enabled: true` in the config
2. Restart Hermes gateway
3. The 60 read-only/reporting tools will be available

## Files

| File | Description |
|------|-------------|
| `meta_ads_bridge.py` | Python stdio-to-HTTP bridge (the fix) |
| `README.md` | This documentation |

## Mutating Tools EXCLUDED

The following tool categories are intentionally excluded from the include list:
- ads_activate_entity, ads_boost_* — publish/boost ads
- ads_create_*, ads_delete_*, ads_update_* — create/delete/update entities
- ads_experiment_*test*(create|update) — create/update experiments
- ads_finalize_*, ads_log_* — finalization and telemetry
- ads_creative_delete, ads_creative_update — creative mutations
- ads_catalog_create, ads_catalog_delete — catalog mutations