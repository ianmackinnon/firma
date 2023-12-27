import os
from pathlib import Path

from dotenv import dotenv_values


class EnvDict(dict):
    def __getitem__(self, k):
        if value := os.environ.get(k, ""):
            return value
        return super().__getitem__(k)
    def get(self, k, default=None):
        if value := os.environ.get(k, ""):
            return value
        return super().get(k, default=default)



def load_env_multi(path_list):
    return EnvDict({k: v for path in path_list for k, v in dotenv_values(path).items()})



def load_env_app(env_path: Path | str, mode: str | None = None):
    path_list = [
        env_path / ".env",
        env_path / ".env.local",
    ]
    if mode:
        path_list += [
            env_path / f".env.{mode}",
            env_path / f".env.{mode}.local",
        ]
    return load_env_multi(path_list)
