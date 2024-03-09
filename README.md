##MFA System
# files

#root dir
- app.py => main file and blueprint  registration
    #Auth dir
        -__init__ => blueprint declaration 
        - models 
        - login and sign up => Authentification Routes 
        - Security => functions (totp gen verify , email ..)
        - MFA => Routes for Security

    #Templates
    - html files all you need to know 
##Main App 
#(1 = finished , 0 = unfinished )
#Done : 
- Authentification
    - Login and passowrd (Login and signup files) 
    - retrieve data from the database 
- Security : 
    - Qr code gen for each user , name of the app and there user name 
#undone 
- verify the qr code  
