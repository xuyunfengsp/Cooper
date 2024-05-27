import hmac
import hashlib
import base64
from flask import Flask, request, abort, jsonify
import requests
from openai import OpenAI
import os

application = Flask(__name__)

# line setting
LINE_API_URL = os.environ.get("LINE_API_URL") # 'https://api.line.me/v2/bot/message/reply'
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN") # 'tSCV+pAm+rW1B7+JSUN5w1BSsFmQQ2ZVFNL2zsDn0SeVUbMWcoxuWMiR9XpHlYf2gy2vFqkNgBfZGF24+vODZrFSsUnt1pf8FefrvdQe5zMjDeF2X2oV4CSj21iHxtUI8+Wgm7lY6CjuzWzPNMfPDgdB04t89/1O/w1cDnyilFU='
CHANNEL_SECRET = os.environ.get("CHANNEL_SECRET") # 'cdc39f7d090883facf1d3d04cdc0c873'
#ins setting
INS_VERIFY_TOKEN = os.environ.get("INS_VERIFY_TOKEN")
INS_SERVICE_API_URL = os.environ.get("INS_SERVICE_API_URL")
INS_ACCESS_TOKEN = os.environ.get("INS_ACCESS_TOKEN")
# openapi setting
client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
)

@application.route("/webhook", methods=['POST'])
def webhook():
    if request.method == 'POST':
        body = request.get_data(as_text=True)
        request_hash = hmac.new(CHANNEL_SECRET.encode('utf-8'),
                                body.encode('utf-8'), hashlib.sha256).digest()
        signature = base64.b64encode(request_hash).decode('utf-8')
        line_signature = request.headers.get('X-Line-Signature')
        print("Request Body:")
        print(body)
        print("Request Headers:")
        print(request.headers)
        if signature != line_signature:
            print("signature:")
            print(signature)
            print("X-Line-Signature:")
            print(line_signature)
            return "error", 400

        incoming_message = request.json
        events = incoming_message['events']
        if len(events) != 0:
            reply_token = events[0]['replyToken']
            user_message = events[0]['message']['text']
            try:
                chat_completion = client.chat.completions.create(
                    messages=[
                        {
                        "role": "user",
                        "content": f'{user_message}',
                        }
                    ],
                    model="gpt-3.5-turbo",
                )
                assistant_message = chat_completion.choices[0].message.content
                reply_message = {
                    'replyToken': reply_token,
                    'messages': [{
                        'type': 'text',
                        'text': f'{assistant_message}'
                    }]
                }
            except Exception as e:
                print(e)
                reply_message = {
                    'replyToken': reply_token,
                    'messages': [{
                        'type': 'text',
                        'text': f'你好！你刚才说了: {user_message}'
                    }]
                }
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {ACCESS_TOKEN}'
            }
            requests.post(
                LINE_API_URL, headers=headers, json=reply_message)
        return 'OK', 200
    else:
        abort(400)


@application.route("/chat", methods=['POST'])
def chat():
    user_message = request.json.get('message')
    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                "role": "user",
                "content": f'say {user_message}',
                }
            ],
            model="gpt-3.5-turbo",
        )
        assistant_message = chat_completion.choices[0].message.content
        return jsonify({"reply": assistant_message})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@application.route("/test", methods=['GET'])
def test():
    return "OK"


@application.route('/webhook-ins', methods=['GET', 'POST'])
def webhook_ins():
    if request.method == 'GET':
        if request.args.get('hub.verify_token') != INS_VERIFY_TOKEN:
            return 'Verification token mismatch', 403
        return request.args.get('hub.challenge')

    if request.method == 'POST':
        data = request.json
        if 'entry' in data:
            for entry in data['entry']:
                for messaging_event in entry.get('messaging', []):
                    if 'message' in messaging_event:
                        sender_id = messaging_event['sender']['id']
                        message_text = messaging_event['message'].get('text')
                        
                        if message_text:
                            reply = get_reply_from_service(message_text)
                            send_message(sender_id, reply)
        return 'EVENT_RECEIVED', 200


def get_reply_from_service(user_message):
    response = requests.post(INS_SERVICE_API_URL, json={'message': user_message})
    return response.json().get('reply')

def send_message(recipient_id, text):
    url = f'https://graph.facebook.com/v11.0/me/messages?ACCESS_TOKEN={INS_ACCESS_TOKEN}'
    payload = {
        'recipient': {'id': recipient_id},
        'message': {'text': text}
    }
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, json=payload, headers=headers)
    return response.json()


if __name__ == "__main__":
    application.run(port=5000)