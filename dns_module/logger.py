"""
Centralized logger configuration and compatibility helpers for the DNS app.

Provides:
- InterceptHandler: bridges stdlib logging to loguru
- LoguruCompat: safe, formatting-friendly wrapper around loguru logger
- configure_logging(app_name): sets up sinks and returns a bound app logger

Retains the existing simple `Logger` class for backward compatibility.
"""
from __future__ import annotations

import os
import sys
import socket
import logging
from pathlib import Path

from loguru import logger


class Logger:
    def __init__(self, directory: str = "/root/celery_app/", log_file: str = "dnslog.log"):
        self.directory = directory
        self.log_file = log_file
        self.logger = self.create_logger()

    def create_logger(self):
        logger.remove()
        logger.add(f"{self.directory}{self.log_file}", colorize=True)
        return logger

    def info(self, message):
        self.logger.info(message)

    def success(self, message):
        self.logger.success(message)

    def error(self, message):
        self.logger.error(message)


class InterceptHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except Exception:
            level = record.levelno
        # forward to loguru, preserve exception info if present
        logger.opt(exception=record.exc_info).log(level, record.getMessage())


class LoguruCompat:
    def __init__(self, lg):
        self._lg = lg

    def _format_msg(self, *args, **kwargs) -> str:
        # If no args, maybe kwargs-only formatting
        if not args:
            if kwargs:
                try:
                    return str(kwargs)
                except Exception:
                    return ""
            return ""

        fmt = args[0]
        rest = args[1:]

        # If first arg is a string, try to format safely:
        if isinstance(fmt, str):
            # 1) Try str.format ({} style). If it succeeds and changed the string, use it.
            if ("{" in fmt and "}" in fmt) or kwargs:
                try:
                    return fmt.format(*rest, **kwargs)
                except Exception:
                    # Fall through to try %-format, then safe fallback
                    pass

            # 2) Try %-format (old-style). Use try/except to avoid raising TypeError.
            if "%" in fmt:
                try:
                    return fmt % rest
                except Exception:
                    # fallback below
                    pass

            # 3) No formatting placeholders or both attempts failed: return a safe joined representation.
            try:
                if rest:
                    return fmt + " " + " ".join(map(str, rest))
                return fmt
            except Exception:
                try:
                    return str(fmt)
                except Exception:
                    return ""
        else:
            # Not a string: join all args into a string
            try:
                return " ".join(map(str, args))
            except Exception:
                try:
                    return str(fmt)
                except Exception:
                    return ""

    def bind(self, **fields):
        try:
            bound = self._lg.bind(**fields)
            return LoguruCompat(bound)
        except Exception:
            return self

    def debug(self, *args, **kwargs):
        msg = self._format_msg(*args, **kwargs)
        try:
            self._lg.debug(msg)
        except Exception:
            try:
                self._lg.debug(str(msg))
            except Exception:
                pass

    def info(self, *args, **kwargs):
        msg = self._format_msg(*args, **kwargs)
        try:
            self._lg.info(msg)
        except Exception:
            try:
                self._lg.info(str(msg))
            except Exception:
                pass

    def warning(self, *args, **kwargs):
        msg = self._format_msg(*args, **kwargs)
        try:
            self._lg.warning(msg)
        except Exception:
            try:
                self._lg.warning(str(msg))
            except Exception:
                pass

    def error(self, *args, **kwargs):
        msg = self._format_msg(*args, **kwargs)
        try:
            self._lg.error(msg)
        except Exception:
            try:
                self._lg.error(str(msg))
            except Exception:
                pass

    def exception(self, *args, **kwargs):
        # Format message if provided, but ensure we never raise.
        msg = self._format_msg(*args, **kwargs) if (args or kwargs) else ""
        try:
            if msg:
                self._lg.exception(msg)
            else:
                self._lg.exception("")  # log current exception traceback
        except Exception:
            try:
                self._lg.error(msg or "exception")
            except Exception:
                pass

    def getChild(self, name: str):
        try:
            child = self._lg.bind(module=name)
            return LoguruCompat(child)
        except Exception:
            return self


def configure_logging(app_name: str = "dns_app") -> LoguruCompat:
    """
    Configure loguru sinks and stdlib logging interception.
    Returns a bound `LoguruCompat` logger for the application.
    """
    # stdout sink
    logger.remove()
    log_level = os.getenv("DNS_APP_LOG_LEVEL", "INFO").upper()
    logger.add(sys.stdout, level=log_level, format="<green>{time}</green> <level>{message}</level>")

    # Optional file sink: configurable via envs, defaults under NFS_BASE/logs
    try:
        base_logs_dir = os.getenv("DNS_APP_LOG_DIR") or os.getenv("DNS_LOG_DIR")
        if not base_logs_dir:
            nfs_base = os.getenv("NFS_BASE", "/mnt/shared")
            base_logs_dir = str(Path(nfs_base) / "logs")
        Path(base_logs_dir).mkdir(parents=True, exist_ok=True)
        # Derive a per-server tag for log file naming (hostname/IP/env override)
        server_tag = (
            os.getenv("DNS_SERVER_TAG")
            or os.getenv("DNS_SERVER_IP")
            or os.getenv("HOSTNAME")
            or socket.gethostname()
        )
        # Sanitize tag for filesystem safety
        server_tag = "".join(ch for ch in server_tag if ch.isalnum() or ch in ("-", "_")) or "server"
        default_log_file = str(Path(base_logs_dir) / f"dns_app.{server_tag}.log")
        log_file = os.getenv("DNS_APP_LOG_FILE") or default_log_file
        rotation = os.getenv("DNS_APP_LOG_ROTATION", "10 MB")
        retention = os.getenv("DNS_APP_LOG_RETENTION", "7 days")
        compression = os.getenv("DNS_APP_LOG_COMPRESSION", "zip")
        logger.add(
            log_file,
            level=log_level,
            enqueue=True,
            backtrace=True,
            diagnose=False,
            rotation=rotation,
            retention=retention,
            compression=compression,
            format="{time} | {level} | {message}"
        )
        logger.info(
            "File logging enabled: {} (server_tag={} rotation={} retention={})",
            log_file,
            server_tag,
            rotation,
            retention,
        )
    except Exception:
        # If file sink cannot be created, continue with stdout only
        pass

    # Bridge stdlib logging through loguru
    logging.root.handlers = [InterceptHandler()]
    logging.root.setLevel(getattr(logging, log_level, logging.INFO))

    # Bound application logger for convenient reuse across modules
    _app_log_raw = logger.bind(app=app_name)
    global _APP_LOGGER
    _APP_LOGGER = LoguruCompat(_app_log_raw)
    return _APP_LOGGER


_APP_LOGGER: LoguruCompat | None = None

def get_app_logger(app_name: str = "dns_app") -> LoguruCompat:
    """Return the configured application logger if available; otherwise bind a lightweight one."""
    global _APP_LOGGER
    if _APP_LOGGER is not None:
        return _APP_LOGGER
    return LoguruCompat(logger.bind(app=app_name))

def get_child_logger(name: str, app_name: str = "dns_app") -> LoguruCompat:
    """Convenience: return a child logger bound with module/name."""
    return get_app_logger(app_name).getChild(name)

__all__ = [
    "Logger",
    "InterceptHandler",
    "LoguruCompat",
    "configure_logging",
    "get_app_logger",
    "get_child_logger",
]
