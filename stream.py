import cv2
import requests

RAILWAY_URL = "http://cyberwatch.up.railway.app/upload_frame"

cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

print("Streaming started... Press Ctrl+C to stop.")

while True:
    ret, frame = cap.read()
    if not ret:
        print("Failed to grab frame.")
        break

    _, jpeg = cv2.imencode('.jpg', frame)
    try:
        requests.post(RAILWAY_URL, data=jpeg.tobytes(), timeout=2)
    except Exception as e:
        print("Error sending frame:", e)

cap.release()
print("Stream stopped.")