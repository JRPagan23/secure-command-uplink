import paho.mqtt.client as mqtt
import json
import time
from crypto_utils import decrypt, verify_hmac, load_key

BROKER = "localhost"
PORT = 8884
TOPIC = "secure/commands"
SECRET_KEY_PATH = "secret.key"

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("✅ Subscriber connected")
        client.subscribe(TOPIC)
    else:
        print(f"❌ Connection failed with code {rc}")

def on_message(client, userdata, msg):
    try:
        secret_key = userdata["secret_key"]
        encrypted_payload = msg.payload
        decrypted_message = decrypt(encrypted_payload, secret_key)

        # Verify HMAC (optional, if you added that)
        if not verify_hmac(decrypted_message, secret_key):
            print("❌ HMAC verification failed")
            return

        # Parse JSON command data
        message_dict = json.loads(decrypted_message)

        # Replay attack protection: check timestamp
        timestamp = message_dict.get("timestamp")
        if timestamp is None:
            print("⚠️ No timestamp found, rejecting message")
            return

        current_time = time.time()
        if current_time - timestamp > 5:
            print("⚠️ Message rejected: too old (possible replay attack)")
            return

        command = message_dict.get("command", "").lower()
        print(f"✅ Received command: {message_dict}")

        # Simulated command execution
        if command == "reboot":
            print("🔄 Rebooting system... (simulated)")
        elif command == "shutdown":
            print("⏹️ Shutting down... (simulated)")
        elif command == "rotate":
            print("🔁 Rotating satellite... (simulated)")
        else:
            print("⚠️ Unknown command.")

    except Exception as e:
        print(f"❌ Failed to decrypt or process message: {e}")

def main():
    secret_key = load_key(SECRET_KEY_PATH)
    client = mqtt.Client(userdata={"secret_key": secret_key})
    client.tls_set(ca_certs="certs/ca.crt",
                   certfile="certs/client.crt",
                   keyfile="certs/client.key")
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(BROKER, PORT, 60)
    client.loop_forever()

if __name__ == "__main__":
    main()
