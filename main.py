# ============================================================
#  AURA :: Python Backend 
#  YOLOv8 + FastAPI + SQLite + Auth + PDF + Camera Stream
#  Run: uvicorn main:app --host 0.0.0.0 --port 19090 --reload
# ============================================================

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import cv2, numpy as np, time, uuid, os
from datetime import datetime
from typing import Optional

from ultralytics import YOLO
from database import init_db, get_db, save_scan, Scan, Detection, User
from auth import auth_router, get_current_user, require_user
from reports import generate_report

# --- App Initialization ---
app = FastAPI(title="AURA Neural Auditor")

# Enable CORS for frontend-backend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)
app.include_router(auth_router)

# Mount static files for frontend access
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse("aura.html")

@app.on_event("startup")
async def startup():
    init_db()
    print("[AURA] Database system initialized.")

# --- YOLOv8 Intelligence Engine ---
print("[AURA] Loading YOLOv8 Neural Network...")
# Using yolov8n.pt for optimal real-time performance
model = YOLO("yolov8n.pt") 
print("[AURA] Intelligence Core: READY")

# --- Global Camera State ---
camera_cap    = None
camera_active = False

# --- Security & Audit Rules ---
DANGER_OBJECTS  = {"knife", "scissors", "gun", "rifle", "pistol", "sword", "baseball bat", "bottle", "machine gun", "grenade", "explosive", "wrench", "crowbar", "hammer", "ax", "saw", "drill"}
CAUTION_OBJECTS = {"car", "truck", "bus", "motorcycle", "bicycle", "backpack", "handbag", "suitcase", "umbrella"}
SAFE_OBJECTS    = {"person", "cat", "dog", "bird", "chair", "sofa", "laptop", "keyboard", "mouse", "cell phone", "book", "cup", "fork", "spoon", "bowl", "clock", "vase"}
THREAT_PRIORITY = {"gun": 10, "rifle": 10, "pistol": 10, "knife": 7, "sword": 7, "baseball bat": 6, "scissors": 4, "bottle": 3}
CATEGORIES      = {"knife": "weapon", "scissors": "weapon", "gun": "weapon", "rifle": "weapon", "pistol": "weapon", "sword": "weapon", "baseball bat": "weapon", "car": "vehicle", "person": "person", "bottle": "object"}

def audit_detection(label, confidence, bbox):
    label_lower = label.lower()
    category = CATEGORIES.get(label_lower, "item")
    
    if label_lower in DANGER_OBJECTS:
        return {"label": label, "confidence": round(confidence, 3), "bbox": bbox, "threat": "DANGER", "threatLevel": 3, "category": category, "priority": THREAT_PRIORITY.get(label_lower, 5), "rationale": f"Identified {label} as high-level threat."}
    if label_lower in SAFE_OBJECTS:
        return {"label": label, "confidence": round(confidence, 3), "bbox": bbox, "threat": "SAFE", "threatLevel": 1, "category": category, "priority": 1, "rationale": f"Identified {label} as benign."}
    return {"label": label, "confidence": round(confidence, 3), "bbox": bbox, "threat": "CAUTION", "threatLevel": 2, "category": category, "priority": 2, "rationale": f"Unknown or suspicious item: {label}."}

def calculate_system_status(audits):
    if not audits: 
        return {"threat": "CLEAR", "level": 0, "summary": "Environment nominal.", "recommendation": "Maintain monitoring."}
    
    danger_count = sum(1 for a in audits if a["threatLevel"] >= 3)
    if danger_count >= 1: 
        return {"threat": "DANGER", "level": 3, "summary": "Threat detected!", "recommendation": "Trigger security protocol."}
    return {"threat": "SAFE", "level": 1, "summary": "Secure environment.", "recommendation": "No action required."}

def process_frame(frame):
    detections = []
    results = model(frame, conf=0.4, verbose=False)
    for box in results[0].boxes:
        class_id = int(box.cls[0])
        x1, y1, x2, y2 = map(int, box.xyxy[0])
        detections.append(audit_detection(model.names[class_id], float(box.conf[0]), {"x": x1, "y": y1, "w": x2-x1, "h": y2-y1}))
    return detections

# --- API Endpoints ---

# Added: System Status Endpoint to fix 'Offline' issue
@app.get("/api/status")
async def get_system_status():
    return {
        "status": "online",
        "timestamp": datetime.now().isoformat(),
        "engine": "YOLOv8n",
        "camera_active": camera_active
    }

@app.get("/api/camera/start")
async def start_camera():
    global camera_cap, camera_active
    if not camera_active:
        camera_cap = cv2.VideoCapture(0)
        if not camera_cap.isOpened():
            raise HTTPException(400, "Hardware error: Camera not accessible.")
        camera_active = True
    return {"status": "success", "message": "Camera stream initiated."}

@app.get("/api/camera/stop")
async def stop_camera():
    global camera_cap, camera_active
    if camera_cap: 
        camera_cap.release()
        camera_cap = None
    camera_active = False
    return {"status": "success", "message": "Camera stream terminated."}

@app.get("/api/camera/frame")
async def get_camera_frame():
    global camera_cap, camera_active
    if not camera_active or not camera_cap: 
        raise HTTPException(400, "Camera is offline.")
    
    success, frame = camera_cap.read()
    if not success: 
        raise HTTPException(500, "Failed to capture video frame.")
    
    audits = process_frame(frame)
    status = calculate_system_status(audits)
    
    # Draw Visual Overlays
    for item in audits:
        box = item["bbox"]
        color = (0, 0, 255) if item["threat"] == "DANGER" else (0, 255, 0)
        cv2.rectangle(frame, (box["x"], box["y"]), (box["x"]+box["w"], box["y"]+box["h"]), color, 2)
        cv2.putText(frame, f"{item['label']}", (box["x"], box["y"]-10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)
    
    _, buffer = cv2.imencode(".jpg", frame)
    return Response(
        content=buffer.tobytes(), 
        media_type="image/jpeg", 
        headers={"X-Threat": status["threat"], "X-Objects": str(len(audits))}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=19090)