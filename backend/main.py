from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes import router
from storage import ensure_data_files


app = FastAPI(title="Signal-style Messaging Backend")

# Do not use allow_credentials=True with allow_origins=["*"] — browsers block that.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event() -> None:
    ensure_data_files()


app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    # Local run (from backend/): `python main.py`
    uvicorn.run("main:app", host="0.0.0.0", port=3001, reload=True)

