import time
import paho.mqtt.subscribe as subscribe
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC

last_light_message_nonce = None

def get_current_time():
    return int(time.time() * 1000000)

def is_message_authentic(key, hash, nonce, ciphertext, last_nonce):
    hasher = HMAC.new(key, ciphertext, SHA256)
    if hasher.hexdigest() != hash:
        # Key False
        return 1
    elif last_nonce != None and int(nonce) - int(last_nonce) < 0:
        # Nonce Expired
        return 2
    else:
        # True
        return 0

def on_message_light(client, userdata, message):
    global last_light_message_nonce
    key = "Sixteen byte key"
    hash = message.payload[:64]
    nonce = message.payload[64:80]
    ciphertext = message.payload[80:]

    message_authenticity = is_message_authentic(key, hash, nonce, ciphertext, last_light_message_nonce)
    if message_authenticity == 1:
        print "Message Not Authenticated - Key False"
    elif message_authenticity == 2:
        print "Message Not Authenticated - Nonce Expired"
    elif message_authenticity == 0:
        print "Message Authenticated"
        last_light_message_nonce = nonce
        cipher = AES.new(key, AES.MODE_CFB, nonce)
        plaintext = cipher.decrypt(ciphertext)
        if plaintext == '0':
            print 'Light Off'
        elif plaintext == '1':
            print 'Light On'
        else:
            print 'Value Not Valid'
    print

if __name__ == "__main__":
    hostname = "localhost"
    subscribe.callback(on_message_light, "things/1/light", hostname=hostname)
