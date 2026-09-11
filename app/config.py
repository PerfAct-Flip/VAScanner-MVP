from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./scanner.db"

    # Nuclei
    nuclei_binary: str = "nuclei"
    nuclei_tags: str = "cve,misconfig"
    nuclei_severity: str = "critical,high,medium,low"
    nuclei_timeout_seconds: int = 600

    # OpenVAS / GVM
    openvas_socket_path: str = "/run/gvmd/gvmd.sock"
    openvas_username: str = "admin"
    openvas_password: str = "admin"
    openvas_port_list_name: str = "All IANA assigned TCP"
    openvas_scan_config_name: str = "Base"
    openvas_scanner_name: str = "OpenVAS Default"
    openvas_connect_timeout_seconds: int = 300
    openvas_poll_timeout_seconds: int = 12 * 60 * 60
    openvas_socket_wait_seconds: int = 60

    # Fernet key used to encrypt scan credentials (SSH/WinRM/SNMP) at rest.
    # Generate one with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    credential_encryption_key: str


settings = Settings()
