import time
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.ml.model_loader import model_manager
from app.routes import predict, model_info

app = FastAPI(
    title="DNS-TunnelGuard ML Backend API",
    description="Machine Learning-Based Detection of DNS Tunneling Attacks Using DNS Traffic Characteristics",
    version="1.0.0"
)

# CORS configuration to allow Vercel and local frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(predict.router)
app.include_router(model_info.router)

@app.get("/")
def root():
    return {
        "project": "DNS-TunnelGuard",
        "description": "AI-Powered DNS Tunneling Detection API",
        "status": "online",
        "model_status": "Loaded" if model_manager.is_loaded else "Heuristic Fallback",
        "documentation": "/docs"
    }

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "model_loaded": model_manager.is_loaded,
        "classes": ["NORMAL", "DNS TUNNELING"]
    }
