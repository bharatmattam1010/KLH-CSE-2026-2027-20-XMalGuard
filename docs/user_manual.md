# XMalGuard User Manual

## System Requirements
- Python 3.11+
- Node.js 18+
- Windows OS (for native PE analysis)

## Installation Steps
### Backend
1. `cd backend`
2. `python -m venv venv`
3. `venv\Scripts\activate`
4. `pip install -r requirements.txt`

### Frontend
1. `cd frontend`
2. `npm install`

## Configuration
Create a `.env` file in the backend directory:
```env
VT_API_KEY=your_virustotal_api_key_here
```

## Training the Model
1. Place dataset CSV in `backend/data/`
2. Run `python scripts/train_model.py`

## Starting the Application
1. **Backend**: `uvicorn main:app --reload`
2. **Frontend**: `npm start`

## Using the Dashboard
- **Uploading a file**: Drag and drop a PE file into the upload zone.
- **Understanding results**: Review the Malicious/Benign verdict and confidence.
- **SHAP explanation**: Check the feature contribution chart to see why the model made its decision.
- **Risk scores**: Review the 0-100 composite risk score and individual threat indicators.
- **Analysis history**: View previously analyzed files in the history tab.
- **Downloading reports**: Click 'Export Report' to save findings as HTML.

## API Usage Examples
```bash
curl -X POST -F "file=@sample.exe" http://localhost:8000/api/v1/analyze
```

## Troubleshooting
- **File too large**: Adjust the max upload size in FastAPI configuration.
- **Missing pefile errors**: Ensure the uploaded file is a valid Windows executable.

## FAQ
- **Does this execute the malware?** No, XMalGuard performs purely static analysis.
