import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    db_path: str
    headscale_url: str
    headscale_api_key: str
    bootstrap_user: str
    bootstrap_pass: str
    totp_issuer: str
    session_cookie_name: str
    session_lifetime_secs: int
    secure_cookies: bool
    # For direct-DB bypass operations
    headscale_data_path: str
    headscale_config_path: str
    headscale_container: str
    prefix_v4: str
    prefix_v6: str


def load_config() -> Config:
    return Config(
        db_path=os.getenv("PANEL_DB_PATH", "/data/panel.sqlite"),
        headscale_url=os.getenv("PANEL_HEADSCALE_URL", "http://headscale:8080"),
        headscale_api_key=os.getenv("PANEL_HEADSCALE_API_KEY", ""),
        bootstrap_user=os.getenv("PANEL_BOOTSTRAP_USER", ""),
        bootstrap_pass=os.getenv("PANEL_BOOTSTRAP_PASSWORD", ""),
        totp_issuer=os.getenv("PANEL_TOTP_ISSUER", "Headscale Panel"),
        session_cookie_name=os.getenv("PANEL_SESSION_COOKIE", "panel_session"),
        session_lifetime_secs=int(os.getenv("PANEL_SESSION_LIFETIME_SECS", "86400")),
        secure_cookies=os.getenv("PANEL_SECURE_COOKIES", "false").lower() == "true",
        headscale_data_path=os.getenv("PANEL_HEADSCALE_DATA_PATH", "/headscale-data"),
        headscale_config_path=os.getenv("PANEL_HEADSCALE_CONFIG_PATH", "/headscale-config/config.yaml"),
        headscale_container=os.getenv("PANEL_HEADSCALE_CONTAINER", "headscale"),
        # Read directly from HEADSCALE_* env (single source of truth shared with Headscale).
        prefix_v4=os.getenv("HEADSCALE_PREFIXES_V4", "100.64.0.0/10"),
        prefix_v6=os.getenv("HEADSCALE_PREFIXES_V6", "fd7a:115c:a1e0::/48"),
    )
