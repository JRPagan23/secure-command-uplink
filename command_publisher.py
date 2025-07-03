import paho.mqtt.client as mqtt
import time
from crypto_utils import encrypt, load_key

BROKER = "localhost"
PORT = 8884
TOPIC = "satellite/commands"
SECRET_KEY_PATH = "secret.key"

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Publisher connected with result code 0")
    else:
        print(f"❌ Publisher failed to connect, return code {rc}")

def main():
    secret_key = load_key(SECRET_KEY_PATH)
    client = mqtt.Client()
    client.on_connect = on_connect
    client.tls_set(ca_certs="certs/ca.crt",
                   certfile="certs/client.crt",
                   keyfile="certs/client.key")
    client.connect(BROKER, PORT, 60)
    client.loop_start()

    while True:
        command = input("Enter command to send (e.g., 'reboot', 'shutdown', 'rotate'):\n> ")
        message = {"command": command}
        encrypted = encrypt(message, secret_key)
        client.publish(TOPIC, encrypted)
        print(f"📤 Command '{command}' sent encrypted.")
        time.sleep(1)

if __name__ == "__main__":
    main()
