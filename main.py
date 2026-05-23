import os
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from crypt_engine import ObsidianEngine

app = FastAPI(title="Obsidian Crypt API", version="1.0.0")

# Enable CORS security protocols for frontend connection
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize our military-grade cryptographic engine
engine = ObsidianEngine()

# Temporary directory to process files securely
UPLOAD_DIR = os.path.join(os.getcwd(), "vault_temp")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/encrypt")
async def encrypt_endpoint(file: UploadFile = File(...), password: str = Form(...)):
    try:
        # Save uploaded file to local temp secure disk
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())
        
        # Execute AES-256 encryption process
        encrypted_path = engine.encrypt_file(file_path, password)
        
        # Clean up original raw file from server for safety
        if os.path.exists(file_path):
            os.remove(file_path)
            
        return {
            "status": "success",
            "message": "File completely encrypted into secure ciphertext binary.",
            "filename": os.path.basename(encrypted_path)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/decrypt")
async def decrypt_endpoint(file: UploadFile = File(...), password: str = Form(...)):
    try:
        # Save encrypted file payload to temp workspace
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())
            
        # Execute decryption & structural verification
        decrypted_path = engine.decrypt_file(file_path, password)
        
        # Clean up temporary .crypt file
        if os.path.exists(file_path):
            os.remove(file_path)
            
        return {
            "status": "success",
            "message": "Cryptographic tag verified. Original file payload recovered.",
            "filename": os.path.basename(decrypted_path)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))