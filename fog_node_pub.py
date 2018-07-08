import time
import paho.mqtt.publish as publish
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC

def get_nonce():
    return str(int(time.time() * 1000000))

def generate_msg(key, plaintext):
    nonce = get_nonce()
    cipher = AES.new(key, AES.MODE_CFB, nonce)
    ciphertext = cipher.encrypt(plaintext)
    hasher = HMAC.new(key, ciphertext, SHA256)
    hash = hasher.hexdigest() 
    msg = str(hash + nonce + ciphertext)

    return msg

if __name__ == "__main__":
    key = "Sixteen byte key"
    expired_nonce = get_nonce()

    # Light Off
    msg = generate_msg(key, '0')
    print "Send Authentic Light Off Message"
    publish.single("things/1/light", msg, hostname="localhost")

    # Wait for 1 second
    print "Wait 1 second"
    time.sleep(1)

    # Light On
    msg = generate_msg(key, '1')
    print "Send Authentic Light On Message"
    publish.single("things/1/light", msg, hostname="localhost")

    # Wait for 1 second
    print "Wait 1 second"
    time.sleep(1)

    # Fake Key
    fake_key = "Sixteen byte keo"
    msg = generate_msg(fake_key, '1')
    print "Send Fake Key Light On Message"
    publish.single("things/1/light", msg, hostname="localhost")

    # Wait for 1 second
    print "Wait 1 second"
    time.sleep(1)

    # Expired Nonce
    cipher = AES.new(key, AES.MODE_CFB, expired_nonce)
    ciphertext = cipher.encrypt('0')
    hasher = HMAC.new(key, ciphertext, SHA256)
    hash = hasher.hexdigest() 
    msg = hash + expired_nonce + ciphertext
    print "Send Expired Nonce Light Off Message"
    publish.single("things/1/light", msg, hostname="localhost")

    # Wait for 1 second
    print "Wait 1 second"
    time.sleep(1)

    # Not Valid Value
    msg = generate_msg(key, '09809098')
    print "Send Not Valid Message"
    publish.single("things/1/light", msg, hostname="localhost")