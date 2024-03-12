import pyotp
import qrcode

# Generate TOTP URI
def generate_totp_uri(username):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(name=username, issuer_name='Secure App')
    return otp_uri

# Generate QR code for TOTP
def generate_qr_code(otp_uri):
    qr = qrcode.QRCode(version=1, box_size=5, border=5)
    qr.add_data(otp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img

# Verify TOTP
def verify_totp(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

#emall verification
def verify_email(email, code):
    pass