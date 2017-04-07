# coding=utf-8
"""
uwsgi --http :8913 --wsgi-file app.py --callable app --processes 4 --threads 1
"""
from flask import request, Flask, jsonify
import logging
from rule_address import run_address_rule

FORMAT = '%(asctime)-15s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT, level=logging.INFO)
app = Flask(__name__, static_folder='static')


@app.route('/api/v1/spam/address', methods=['GET', 'POST'])
def verify_new_address():
    address_param = request.args.to_dict()
    return jsonify(**run_address_rule(address_param))


@app.route('/api/v1/spam/order')
def verify_order():
    pass


@app.route('/api/v1/spam/note', methods=['GET', 'POST'])
def verity_note():
    pass


@app.route('/admin/rules')
def admin_rules():
    pass


@app.route('/')
def root():
    pass


if __name__ == '__main__':
    app.run(debug=True, port=8913, host='0.0.0.0')
