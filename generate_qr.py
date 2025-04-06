import  qrcode

number = "1234567890"  #enter vmid

# Generate QR code
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(number)
qr.make(fit=True)

img = qr.make_image(fill="black", back_color="white")
img.save("qr_code.png")

print("QR Code saved as qr_code.png")
