from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from supabase import create_client, Client
import httpx

# ── Supabase config ──────────────────────────────────────────────
SUPABASE_URL = "https://laimqzppmletwkljrsfb.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxhaW1xenBwbWxldHdrbGpyc2ZiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI2MTE0NjksImV4cCI6MjA4ODE4NzQ2OX0.CJvIzObHozXGAMmUCQfPEQtYh5xeZbEwpImUcK9fCQA"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── App setup ────────────────────────────────────────────────────
app = FastAPI(title="SupplyChain AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# ── Role → HTML page mapping ─────────────────────────────────────
ROLE_REDIRECTS = {
    "admin":        "admin1.html",
    "seller":       "seller1.html",
    "manufacturer": "manufacturer1.html",
}

# ── Request models ───────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str = ""
    role: str = "seller"


# ════════════════════════════════════════════════════════════════
#  GET /health
# ════════════════════════════════════════════════════════════════
@app.get("/health")
async def health():
    return {"status": "ok", "message": "SupplyChain AI backend is running"}


# ════════════════════════════════════════════════════════════════
#  POST /register
# ════════════════════════════════════════════════════════════════
@app.post("/register")
async def register(req: RegisterRequest):
    try:
        print(f"[REGISTER] Attempt for: {req.email} as {req.role}")

        if req.role not in ["admin", "seller", "manufacturer"]:
            return {"status": "error", "message": "Invalid role. Must be admin, seller, or manufacturer"}

        if len(req.password) < 6:
            return {"status": "error", "message": "Password must be at least 6 characters"}

        # 1. Create user in Supabase Auth
        auth_response = supabase.auth.sign_up({
            "email":    req.email,
            "password": req.password,
        })

        user = auth_response.user
        if not user:
            return {"status": "error", "message": "Registration failed. Please try again."}

        print(f"[REGISTER] User created: {user.id}")

        # 2. Insert into profiles table
        try:
            supabase.table("profiles").insert({
                "id":        str(user.id),
                "email":     req.email,
                "role":      req.role,
                "full_name": req.full_name or req.email.split("@")[0],
            }).execute()
            print(f"[REGISTER] Profile created for: {req.email} role: {req.role}")
        except Exception as profile_err:
            print(f"[REGISTER] Profile insert failed: {profile_err}")
            # User was created in auth, still return success
            # They can log in and profile will use defaults

        return {
            "status":  "success",
            "message": "Account created successfully! Please sign in.",
        }

    except Exception as e:
        error_msg = str(e)
        print(f"[REGISTER] Exception: {error_msg}")
        if "already registered" in error_msg or "already exists" in error_msg or "duplicate" in error_msg.lower():
            return {"status": "error", "message": "This email is already registered. Please sign in."}
        return {"status": "error", "message": f"Registration failed: {error_msg}"}


# ════════════════════════════════════════════════════════════════
#  POST /login
# ════════════════════════════════════════════════════════════════
@app.post("/login")
async def login(req: LoginRequest):
    try:
        print(f"[LOGIN] Attempt for: {req.email}")

        # 1. Authenticate with Supabase Auth
        auth_response = supabase.auth.sign_in_with_password({
            "email":    req.email,
            "password": req.password
        })

        user = auth_response.user
        if not user:
            return {"status": "error", "message": "Invalid email or password"}

        print(f"[LOGIN] Auth success for: {user.email}")

        # 2. Fetch role from profiles table
        role      = "seller"
        full_name = req.email.split("@")[0]

        try:
            profile = (
                supabase.table("profiles")
                .select("role, full_name")
                .eq("id", user.id)
                .single()
                .execute()
            )
            if profile.data:
                role      = profile.data.get("role", "seller")
                full_name = profile.data.get("full_name", full_name)
                print(f"[LOGIN] Profile — role: {role}, name: {full_name}")
        except Exception as profile_error:
            print(f"[LOGIN] Profile fetch failed: {profile_error} — using defaults")

        redirect = ROLE_REDIRECTS.get(role, "login.html")
        print(f"[LOGIN] Redirecting to: {redirect}")

        return {
            "status":   "success",
            "message":  f"Welcome, {full_name}!",
            "role":     role,
            "redirect": redirect,
            "token":    auth_response.session.access_token,
            "user": {
                "id":        str(user.id),
                "email":     user.email,
                "full_name": full_name,
                "role":      role,
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        print(f"[LOGIN] Exception: {error_msg}")
        if "Invalid login credentials" in error_msg or "invalid_credentials" in error_msg:
            return {"status": "error", "message": "Invalid email or password. Please try again."}
        if "Email not confirmed" in error_msg:
            return {"status": "error", "message": "Please confirm your email before logging in."}
        if "timed out" in error_msg.lower() or "timeout" in error_msg.lower():
            return {"status": "error", "message": "Connection timed out. Please check your internet and try again."}
        return {"status": "error", "message": f"Login failed: {error_msg}"}


# ════════════════════════════════════════════════════════════════
#  GET /me
# ════════════════════════════════════════════════════════════════
@app.get("/me")
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        user_response = supabase.auth.get_user(token)

        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        user = user_response.user

        try:
            profile = (
                supabase.table("profiles")
                .select("role, full_name")
                .eq("id", user.id)
                .single()
                .execute()
            )
            role      = profile.data.get("role", "seller") if profile.data else "seller"
            full_name = profile.data.get("full_name", user.email) if profile.data else user.email
        except Exception:
            role      = "seller"
            full_name = user.email.split("@")[0]

        return {
            "status":    "success",
            "id":        str(user.id),
            "email":     user.email,
            "full_name": full_name,
            "role":      role,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ════════════════════════════════════════════════════════════════
#  POST /logout
# ════════════════════════════════════════════════════════════════
@app.post("/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        supabase.auth.sign_out()
        return {"status": "success", "message": "Logged out successfully"}
    except Exception:
        return {"status": "success", "message": "Logged out"}


# ════════════════════════════════════════════════════════════════
#  GET /manufacturers
# ════════════════════════════════════════════════════════════════
@app.get("/manufacturers")
async def get_manufacturers(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Unauthorized")

        result = (
            supabase.table("manufacturers")
            .select("*")
            .order("created_at", desc=True)
            .execute()
        )
        return {"status": "success", "data": result.data, "count": len(result.data)}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ════════════════════════════════════════════════════════════════
#  GET /manufacturers/{id}
# ════════════════════════════════════════════════════════════════
@app.get("/manufacturers/{manufacturer_id}")
async def get_manufacturer(
    manufacturer_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        token = credentials.credentials
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Unauthorized")

        result = (
            supabase.table("manufacturers")
            .select("*")
            .eq("id", manufacturer_id)
            .single()
            .execute()
        )

        if not result.data:
            raise HTTPException(status_code=404, detail="Manufacturer not found")

        return {"status": "success", "data": result.data}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ════════════════════════════════════════════════════════════════
#  GET /profile
# ════════════════════════════════════════════════════════════════
@app.get("/profile")
async def get_profile(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Unauthorized")

        user = user_response.user
        profile = (
            supabase.table("profiles")
            .select("*")
            .eq("id", user.id)
            .single()
            .execute()
        )

        return {
            "status": "success",
            "data": {
                "id":        str(user.id),
                "email":     user.email,
                "full_name": profile.data.get("full_name", ""),
                "role":      profile.data.get("role", "seller"),
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ════════════════════════════════════════════════════════════════
#  Static files — serve HTML pages from current directory
#  Must be LAST so API routes take priority
# ════════════════════════════════════════════════════════════════
app.mount("/", StaticFiles(directory=".", html=True), name="static")


# ════════════════════════════════════════════════════════════════
#  Run with:  python -m uvicorn main:app --reload --port 5000
# ════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)
