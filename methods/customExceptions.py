def signup_exception(e):
    status = {
        "User created successfully" : 201100,
        
        "Invalid phone number" : 400100,
        "Invalid Email format" : 400101,
        "Missing fields" : 400102,
        
        
        "Username already exists" : 409100,
        "Email already exists" : 409101,
        "Phone Number already exists" : 409102,
        "Duplicate entry for unique field":409103,
        'Missing fields':400103,
        'Headers Invalid':409104,
        "Required headers not found":400105,
        'Full Name must contain only Alphabets':400106,
        'password must contain greater than 7 letters': 400107,
        
        
        'Database connection error ': 500100,
        'Data Integrity Violation' : 500101,
        'Resource Exhaustion' : 500102,
    }
    
    return status[e]
    
    

def signin_exception(e):
    status = {
        "Login successful" : 200200,
        "Invalid username or password" : 400201,
        "Username is  missing":400202,
        "Password is missing" : 400203,
        "User not found" : 400204,
        "Email already exists":400205,
        
        
        'Database connection error ': 500200,
        'Data Integrity Violation' : 500201,
        'Resource Exhaustion' : 500202,
        
    }
    
    return status[e]
        
        
    
    
    
def forgot_password_exception(e):
    status = {
        "Invalid Email format" : 400301,
        "Invalid Email" : 400302,
        "Email missing" : 400303,
        'Email is required' : 400304,
        
        'Database connection error ': 500300,
        'Data Integrity Violation' : 500301,
        'Resource Exhaustion' : 500302,
    }
    
    return status[e]
    
    
def reset_password_exception(e):
    status = {
        "Missing or Invalid Password" : 400401,
        "Invalid or expired token" : 400402,
        "Passwords did not match" : 400403,
        "password has been upodated successfully" : 200400,
        'Email is required' : 401404,
        'Token is missing' : 401405,
        'Invalid Headers' : 400404,
        'Token is invalid' : 400405,
        
        "password reset link has been sent to your mail": 200405,
        
        'Database connection error ': 500400,
        'Data Integrity Violation' : 500401,
        'Resource Exhaustion' : 500402,
    }
    
    return status[e]

def image_upload_exception(e):
    status = {
        "Image uploaded successfully" : 200500,
        "Failed to upload image" : 500501,
        
        'Database connection error ': 500500,
        'Data Integrity Violation' : 500501,
        'Resource Exhaustion' : 500502,
    }
    
    
    
    
    
    
    
    
    
    
    # 409 Conflict
    # 201 created
    # 400 Bad Request
    # 401 Unauthorized
    # 403 Forbidden
    # 404 Not Found
    # 405 Method Not Allowed
    # 406 Not Acceptable
    # 407 Proxy Authentication Required
    # 408 Request Timeout
    # 409 Conflict
    # 410 Gone
    # 411 Length Required
    # 412 Precondition Failed
    # 413 Request Entity Too Large
    # 414 Request-URI Too Long
    # 415 Unsupported Media Type
    # 416 Requested Range Not Satisfiable
    # 417 Expectation Failed
    # 418 I'm a teapot
    # 422 Unprocessable Entity
    # 423 Locked
    # 424 Failed Dependency
    # 425 Unordered Collection