import logging
import os
import shutil
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.analyze import router as analyze_router
from .api.history import router as history_router
from .api.health import router as health_router
from .api.reports import router as reports_router
from .database import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

TEMP_UPLOADS_DIR = os.path.join(os.path.dirname(__file__), "temp_uploads")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for FastAPI app.
    Initializes database and creates temp directory on startup.
    Cleans up temp directory on shutdown.
    """
    logger.info("Starting XMalGuard API...")
    
    # Initialize database
    init_db()
    
    # Create temp directory
    os.makedirs(TEMP_UPLOADS_DIR, exist_ok=True)
    logger.info(f"Temporary uploads directory created at {TEMP_UPLOADS_DIR}")
    
    yield
    
    logger.info("Shutting down XMalGuard API...")
    # Clean up temp directory
    if os.path.exists(TEMP_UPLOADS_DIR):
        try:
            shutil.rmtree(TEMP_UPLOADS_DIR)
            logger.info("Temporary uploads directory cleaned up.")
        except Exception as e:
            logger.error(f"Failed to clean up temp directory: {e}")

app = FastAPI(
    title="XMalGuard API",
    description="Explainable and Threat-Aware AI Framework for Static Malware Detection",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(analyze_router, prefix="/api")
app.include_router(history_router, prefix="/api")
app.include_router(health_router, prefix="/api")
app.include_router(reports_router, prefix="/api")

@app.get("/")
def root():
    """
    Root endpoint returning basic API information.
    """
    return {
        "message": "XMalGuard API",
        "version": "1.0.0",
        "docs": "/docs"
    }
