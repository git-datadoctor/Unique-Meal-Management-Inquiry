import bcrypt

def hash_password(password):
    """
    Hash a password using bcrypt.
    
    Args:
        password (str): The plain text password to hash.
        
    Returns:
        str: The hashed password.
    """
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

def verify_password(plain_password, hashed_password):
    """
    Verify a plain text password against a hashed password.
    
    Args:
        plain_password (str): The plain text password to verify.
        hashed_password (str): The hashed password to verify against.
        
    Returns:
        bool: True if the password matches, False otherwise.
    """
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
