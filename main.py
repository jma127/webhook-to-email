#!/usr/bin/env python3

import hmac
from email.mime.text import MIMEText
import json
import pathlib
import smtplib
import ssl
import traceback

from flask import Flask, jsonify, request


app = Flask(__name__)

def _init_hmac_key():
    with open(str(pathlib.Path(__name__).parent / 'ghs'), 'rb') as infile:
        return infile.read().strip()
_HMAC_KEY = _init_hmac_key()

def _init_smtp_params():
    with open(str(pathlib.Path(__name__).parent / 'smtp.json'), 'r') as infile:
        return json.load(infile)
_SMTP_PARAMS = _init_smtp_params()


@app.route('/webhook-to-email', methods=['POST'])
def webhook():
    success = False
    error = None

    signature = 'sha1=' + hmac.new(_HMAC_KEY, msg=request.data,
                                   digestmod='sha1').hexdigest()
    if not hmac.compare_digest(signature,
               request.headers.get('X-Hub-Signature', '')):
        success = False
        error = 'HMAC verification failed'

    elif not request.json:
        success = False
        error = 'No JSON'

    else:
        payload = request.json
        success = True
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(_SMTP_PARAMS['server'], _SMTP_PARAMS['port'],
                              context=context) as smtpcon:
            try:
                msg = MIMEText(json.dumps(payload, sort_keys=True), 'plain')
                msg['From'] = _SMTP_PARAMS['from']
                msg['To'] = _SMTP_PARAMS['to']
                msg['Subject'] = '[Github Webhook] ' + \
                                  request.headers.get('X-GitHub-Event', '')

                smtpcon.login(
                    _SMTP_PARAMS['username'], _SMTP_PARAMS['password'])
                smtpcon.send_message(msg)
                success = True
            except Exception:
                traceback.print_exc()
                success = False
                error = 'Error sending mail'

    ret = {'success': success}
    if error:
        ret['error'] = error

    print(ret)
    return jsonify(ret)


def main():
    app.run(debug=False, host='0.0.0.0', port='26263')


if __name__ == '__main__':
    main()
