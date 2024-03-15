import smtplib
from email.mime.text import MIMEText

def send_mail(sender, sender_pswd, receiver, key, dev_eui):
    try:
        s = smtplib.SMTP('smtp.gmail.com', 587) #using port 587
        s.starttls()
        s.login(sender,sender_pswd)
        message = MIMEText('Your device with dev_eui: \"'+ dev_eui + '\" is currently using an exposed key: \"' +key +'\". \nDue to security concerns, your requests are being dropped.')
        message['Subject'] = '[Warning] Your key is unsafe'
        message['From'] = sender
        message['To'] = receiver

        s.send_message(message)
        s.quit()
        print("Successfully sent!")
    except Exception:
        print("Error: unable to send email")

if __name__ == '__main__':
    sender = "lora.cs219@gmail.com"
    sender_pswd = "rnppboitedgdxgbk"
    receiver = "longyunze2000@gmail.com"
    key = "621156e57497eb32f619202c9bdb1bca"
    dev_eui = "0000503221f1f72c"
    send_mail(sender,sender_pswd,receiver, key, dev_eui) 