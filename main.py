# Simple FastAPI app for user management
# Features:
# - Users can search by ID to view their data in a table
# - Admin can login and manage (add, edit, delete) user data

# Import required modules
from fastapi import FastAPI, HTTPException, Depends, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Database setup - using MySQL from XAMPP
DATABASE_URL = "mysql+pymysql://root:@localhost/user_management"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# User model - stores user data
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), index=True)
    contact = Column(String(20), index=True)  # Contact/phone number
    date = Column(Date)  # Date as DATE type
    amount = Column(String(50))  # Amount as string to handle various formats

# Admin model - stores admin credentials
class Admin(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    password = Column(String(255))

# Create tables in database
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI()

# Setup templates for HTML pages
templates = Jinja2Templates(directory="templates")

# Password hashing for admin passwords
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic models for data validation
# class UserCreate(BaseModel):
#     name: str
#     email: str

# class UserOut(BaseModel):
#     id: int
#     name: str
#     email: str
#     class Config:
#         orm_mode = True

class AdminCreate(BaseModel):
    username: str
    password: str

class AdminOut(BaseModel):
    id: int
    username: str
    class Config:
        orm_mode = True

# Database session dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Password functions
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password or pwd_context.verify(plain_password, hashed_password)
# Authenticate admin
def authenticate_admin(db, username: str, password: str):
    admin = db.query(Admin).filter(Admin.username == username).first()
    if not admin or not verify_password(password, admin.password):
        return False
    return admin

# Get current admin from cookie
def get_current_admin(admin_token: str = Cookie(None), db: SessionLocal = Depends(get_db)):
    if not admin_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    admin = db.query(Admin).filter(Admin.username == admin_token).first()
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid token")
    return admin

# Endpoints

# Homepage - form to search user by ID
@app.get("/", response_class=HTMLResponse)
def homepage(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Search user by contact and filter by month/year
@app.post("/search", response_class=HTMLResponse)
def search_user(request: Request, contact: str = Form(...), month: int = Form(None), year: int = Form(None), db: SessionLocal = Depends(get_db)):
    # Find users by contact number
    users = db.query(User).filter(User.contact == contact).all()
    if not users:
        return templates.TemplateResponse("error.html", {"request": request, "message": "No records found for this contact"})
    # Filter by month and year if provided
    if month and year:
        users = [u for u in users if u.date and u.date.month == month and u.date.year == year]
    return templates.TemplateResponse("user.html", {"request": request, "users": users, "contact": contact, "month": month, "year": year})

# Search user with AJAX support for dynamic filtering
@app.get("/search")
def search_user_dynamic(request: Request, contact: str, month: int = None, year: int = None, db: SessionLocal = Depends(get_db)):
    # Find users by contact number
    users = db.query(User).filter(User.contact == contact).all()
    if not users:
        return {"users": []}
    # Filter by month and year if provided
    if month and year:
        users = [u for u in users if u.date and u.date.month == month and u.date.year == year]
    elif month:
        users = [u for u in users if u.date and u.date.month == month]
    elif year:
        users = [u for u in users if u.date and u.date.year == year]
    
    # Convert to dict format for JSON response
    users_data = [
        {
            "id": u.id,
            "name": u.name,
            "contact": u.contact,
            "date": str(u.date),
            "amount": u.amount
        }
        for u in users
    ]
    return {"users": users_data}

# Admin login page
@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_form(request: Request):
    return templates.TemplateResponse("admin_login.html", {"request": request})

# Admin login - check credentials, set cookie, redirect to admin panel
@app.post("/admin/login")
def admin_login(username: str = Form(...), password: str = Form(...), db: SessionLocal = Depends(get_db)):
    admin = authenticate_admin(db, username, password)
    if not admin:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    response = RedirectResponse(url="/admin", status_code=302)
    response.set_cookie(key="admin_token", value=username)
    return response

# Admin panel - view all users with month/year filter, add new user, edit/delete links
@app.get("/admin")
def admin_panel(request: Request, month: int = None, year: int = None, db: SessionLocal = Depends(get_db), current_admin: Admin = Depends(get_current_admin)):
    # Get all users or filter by month/year if provided
    users = db.query(User).all()
    if month and year:
        users = [u for u in users if u.date and u.date.month == month and u.date.year == year]
    elif month:
        users = [u for u in users if u.date and u.date.month == month]
    elif year:
        users = [u for u in users if u.date and u.date.year == year]
    
    # Check if this is an AJAX request (looking for JSON response)
    if request.headers.get("accept") == "application/json":
        users_data = [
            {
                "id": u.id,
                "name": u.name,
                "contact": u.contact,
                "date": str(u.date),
                "amount": u.amount
            }
            for u in users
        ]
        return {"users": users_data}  # Return as dict that FastAPI will convert to JSON
    
    # Return HTML response for regular page loads
    return templates.TemplateResponse("admin.html", {"request": request, "users": users, "month": month, "year": year})

# Add new user (admin only)
@app.post("/admin/users")
def create_user(name: str = Form(...), contact: str = Form(...), date: str = Form(...), amount: str = Form(...), db: SessionLocal = Depends(get_db), current_admin: Admin = Depends(get_current_admin)):
    # Convert string date to date object
    user_date = datetime.strptime(date, "%Y-%m-%d").date()
    user = User(name=name, contact=contact, date=user_date, amount=amount)
    db.add(user)
    db.commit()
    return RedirectResponse(url="/admin", status_code=302)

# Edit user page
@app.get("/admin/edit/{user_id}", response_class=HTMLResponse)
def edit_user_form(request: Request, user_id: int, db: SessionLocal = Depends(get_db), current_admin: Admin = Depends(get_current_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return templates.TemplateResponse("error.html", {"request": request, "message": "User not found"})
    return templates.TemplateResponse("edit_user.html", {"request": request, "user": user})

# Update user data
@app.post("/admin/edit/{user_id}")
def update_user(user_id: int, name: str = Form(...), contact: str = Form(...), date: str = Form(...), amount: str = Form(...), db: SessionLocal = Depends(get_db), current_admin: Admin = Depends(get_current_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Convert string date to date object
    user_date = datetime.strptime(date, "%Y-%m-%d").date()
    user.name = name
    user.contact = contact
    user.date = user_date
    user.amount = amount
    db.commit()
    return RedirectResponse(url="/admin", status_code=302)

# Delete user confirmation page
@app.get("/admin/delete/{user_id}", response_class=HTMLResponse)
def delete_user_confirm(request: Request, user_id: int, db: SessionLocal = Depends(get_db), current_admin: Admin = Depends(get_current_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return templates.TemplateResponse("error.html", {"request": request, "message": "User not found"})
    return templates.TemplateResponse("delete_confirm.html", {"request": request, "user": user})

# Delete user
@app.post("/admin/delete/{user_id}")
def delete_user(user_id: int, db: SessionLocal = Depends(get_db), current_admin: Admin = Depends(get_current_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return RedirectResponse(url="/admin", status_code=302)

# Admin logout
@app.get("/admin/logout")
def logout():
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("admin_token")
    return response

# Create admin (for initial setup)
@app.post("/admin/", response_model=AdminOut)
def create_admin(admin: AdminCreate, db: SessionLocal = Depends(get_db)):
    admin_db = Admin(username=admin.username, password=get_password_hash(admin.password))
    db.add(admin_db)
    db.commit()
    db.refresh(admin_db)
    return admin_db

# Run the app with uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
