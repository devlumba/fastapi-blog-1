from pydantic_settings import BaseSettings

tags_metadata_raw = [
    # {
    #     "name": "users",
    #     "description": "Operations with users. The **login** logic is also here.",
    # },
    # {
    #     "name": "items",
    #     "description": "Manage items. So _fancy_ they have their own docs.",
    #     "externalDocs": {
    #         "description": "Items external docs",
    #         "url": "https://fastapi.tiangolo.com/",
    #     },
    # },
    {
        "name": "routes",
        "description": "all the routes so far"
    }
]


class Settings(BaseSettings):
    secret_key: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1
    tags_metadata: list = tags_metadata_raw
    environment: str = "development"

    class Config:
        env_file = ".env"  # I don't have it yet, for storing variables locally and gitignore them


settings = Settings()

