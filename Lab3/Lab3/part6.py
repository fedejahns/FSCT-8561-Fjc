import pyotp

secret = pyotp.random_base32()

totp = pyotp.TOTP(secret)

current_otp = totp.now()

print("Current OTP:", current_otp)


def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)


print("Current OTP valid:", verify_otp(secret, current_otp))
print("Wrong OTP valid:", verify_otp(secret, "123456"))