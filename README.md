# MFA app

## Files
### root dir
- app.py -> main file and blueprint  registration
    #### Auth dir
        -__init__ -> blueprint declaration 
        - models 
        - login and sign up -> Authentification Routes 
        - Security -> functions (totp gen verify , email ..)
        - MFA -> Routes for Security

    #### Templates
    - html files all you need to know 
__________________________________________________________________________________
## Main App 
### Technology currently working with :
    - Web app  -> python + flask 
    - Database -> MongoDB
    - TOTP -> pyotp  
    - SSO technology -> Keycloak : Open Source Solution 
(1 = finished , 0 = unfinished )
- Authentification

    - Login and passowrd (Login and signup files)  1
    - Database Connection  1 
- Security : 
    - TOTP token generation for each user , URI -> Name of app + name of the user 1 
    - Email  0  
    - Enhanced Features for authentificatiom :      0
        -  Emails 
        -  hardware  
        -  notification push approvale
        -  Social Login 

- SSO Applicatoon for test (still searching) 
    - SMTP 
    - FTP
