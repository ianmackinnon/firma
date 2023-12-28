import os
from pathlib import Path

from dotenv import load_dotenv, dotenv_values



def env_app_path_list(
        env_path: Path | str,
        mode: str | None = None
) -> list[Path]:
    path_list = [
        env_path / ".env",
        env_path / ".env.local",
    ]
    if mode:
        path_list += [
            env_path / f".env.{mode}",
            env_path / f".env.{mode}.local",
        ]
    return path_list



def load_env_app(
        env_path: Path | str,
        mode: str | None = None
) -> None:
    for path in env_app_path_list(env_path, mode=mode):
        load_dotenv(path)



def env_values_multi(path_list):
    return {k: v for path in path_list for k, v in dotenv_values(path).items()}



def env_app_values(env_path: Path | str, mode: str | None = None) -> dict:
    return env_values_multi(env_app_path_list(env_path, mode=mode))
