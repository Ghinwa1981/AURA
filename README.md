# AURA — Strategic Neural Auditor 

> **AURA** is a real-time AI-powered security intelligence platform that detects threats in images, videos, text, and live camera feeds using YOLOv8, FastAPI, and LLM-based natural language analysis.


## Project Description

AURA (Strategic Neural Auditor) is a comprehensive AI-powered security intelligence platform developed as a graduation project for Neurobotics Academy. It combines multiple machine learning models to analyze images, videos, and text for threat detection and classification in real time.

The system follows a three-tier architecture:

| Layer | Technologies |
|-------|-------------|
| **AI Layer** | YOLOv8n · Emotion Detection · Groq LLM · OpenCV |
| **API Layer** | FastAPI · SQLAlchemy · JWT Auth · PDF Generator |
| **Frontend Layer** | HTML5/CSS3/JS · Chart.js · AURA Dashboard |


## Features

| Feature | Description |
|---------|-------------|
| Image Intelligence | Upload an image — YOLOv8 detects 80+ object classes — threat classification with bounding boxes |
| Video Intelligence | Frame-by-frame video analysis — visual threat timeline — peak threat report |
| Text Intelligence | Multi-language text analysis via Groq LLM (llama-3.3-70b) — entity extraction + threat scoring |
| Live Camera Stream | Real-time webcam monitoring — YOLO detection overlay — live threat badge |
| Authentication | JWT-based login/register with bcrypt password hashing and role-based access |
| Analytics Dashboard | Threat distribution charts · scan history · top detected objects |
| PDF Reports | Professional PDF security reports for every scan, downloadable on demand |
| Scan History | All scans saved to SQLite — filterable history view |


## Technologies Used

### Backend
- **Python 3.10** — Primary language
- **FastAPI** — REST API framework (auto-generates Swagger docs at `/docs`)
- **YOLOv8n** (Ultralytics) — Object detection, 80 COCO classes
- **OpenCV** — Image/video processing and camera access
- **SQLAlchemy + SQLite** — ORM and embedded database
- **JWT / bcrypt** — Authentication and password hashing
- **ReportLab** — PDF report generation
- **Uvicorn** — ASGI server
- **Groq API** — LLM inference (llama-3.3-70b)

### Frontend
- **HTML5 / CSS3 / JavaScript ES6+**
- **Chart.js** — Interactive threat charts
- **Tailwind CSS** — Utility-first styling
- **Orbitron / Share Tech Mono** — Display typography


## Project Structure

```
AURA_Project/
|
|-- main.py              # FastAPI application — all API endpoints, YOLOv8, camera
|-- database.py          # SQLAlchemy models: User, Scan, Detection
|-- auth.py              # Authentication: registration, login, JWT management
|-- reports.py           # ReportLab PDF report generator
|-- aura.html         # Web frontend — dashboard, auth, all modules
|
|-- yolov8n.pt           # YOLOv8 nano model (~6MB, auto-downloaded on first run)
|-- aura.db              # SQLite database (auto-created on first run)
|
|-- README.md            # This file
```


## Installation

### Prerequisites

- Windows 10/11 with **Anaconda** installed
- Python 3.10
- Modern browser (Chrome, Firefox, Edge)
- Webcam (optional — for Live Camera feature)
- Free **Groq API key** from console.groq.com (for Text Intelligence)

### Step-by-Step Setup

```bash
# 1. Create Anaconda environment
conda create -n aura_python python=3.10 -y

# 2. Activate environment
conda activate aura_python

# 3. Install all dependencies
pip install ultralytics fastapi uvicorn python-multipart opencv-python pillow sqlalchemy reportlab python-jose passlib bcrypt aiofiles

# 4. Navigate to your project folder
cd C:\Users\[your-username]\AURA

# 5. Start the backend server
uvicorn main:app --host 0.0.0.0 --port 19090 --reload
```

### Open the Application

- Open `aura.html` directly in your browser, **or**
- Navigate to http://localhost:19090

> **Note:** The `yolov8n.pt` model (~6MB) is auto-downloaded on the first run. Ensure you have an internet connection.

---

## Usage

### 1. Authentication
Register a new operator account or use the **Demo Access** button to skip login.

### 2. Image Intelligence
Go to **Image Intel** — drag and drop or upload an image — click **Analyze Image** — view detected objects, threat level, confidence scores, and bounding boxes.

### 3. Video Intelligence
Go to **Video Intel** — upload an MP4/AVI/MOV file — click **Analyze Video** — view the threat timeline, click segments for frame details.

### 4. Text Intelligence
Go to **Text Intel** — enter your Groq API key — paste any text (any language) — click **Analyze Text** — view threat level, semantic breakdown, and extracted entities.

### 5. Live Camera Stream
Go to **Neural Stream** — click **Activate Stream** — real-time YOLO detection runs on your webcam feed at ~3 FPS.

### 6. PDF Reports
Go to **Mission Log** — click **PDF** next to any scan to download a professional report.

---

## API Reference

The backend runs on port `19090`. Full interactive docs: http://localhost:19090/docs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | System health, model info, camera state |
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login and receive JWT token |
| GET | `/api/auth/me` | Get current user info (requires Bearer token) |
| POST | `/api/analyze` | Analyze image (raw binary body) |
| POST | `/api/video` | Analyze video (raw binary body) |
| GET | `/api/camera/start` | Start webcam capture |
| GET | `/api/camera/stop` | Stop webcam capture |
| GET | `/api/camera/frame` | Get current analyzed frame + threat headers |
| GET | `/api/history` | Get scan history |
| GET | `/api/stats` | Get threat distribution statistics |
| GET | `/api/report/{scan_id}` | Download PDF report for a scan |

---

## Threat Classification System

AURA uses a four-level threat classification:

| Level | Trigger |
|-------|---------|
| **SAFE** | All objects are benign (person, laptop, chair, cat...) |
| **CAUTION** | Suspicious context (backpack, vehicle, suitcase...) |
| **DANGER** | Confirmed threat detected (knife, scissors, baseball bat...) |
| **CRITICAL** | Weapon + person in same frame / fear emotion / multiple simultaneous threats |

### Contextual Escalation Rules
- Weapon + Person in same frame — Automatically escalates to CRITICAL
- Two or more DANGER objects — Escalates to CRITICAL
- Fear emotion detected on face — Escalates to CRITICAL

---

## Future Improvements

- IP camera / RTSP stream support
- Mobile-responsive PWA version
- Real-time alert notifications (email / SMS)
- Multi-camera dashboard
- Cloud deployment (AWS / Azure)
- Custom threat rule builder for operators
- Export analytics to Excel / CSV
- Arabic UI localization

---

## Developer

**Developed for:** Paper Airplanes — AI Course / Graduation Project 2026
**Student:** Ghinwa Allaoui & Riam Abbas
**Tutor:** Mulham Fetna
**Mentor:** Hala Dagher
**Technologies:** YOLOv8 · FastAPI · SQLite · OpenCV · Groq LLM
**Github:** Ghinwa1981 Riam24


*AURA — Neural Threat Mitigation: ACTIVE*
