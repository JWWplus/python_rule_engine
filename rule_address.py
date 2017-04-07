# coding=utf-8
"""
从该账户下绑定的手机号、收件地址中包含的手机号、收件人手机号三处提取手机号，分别记为A、B、C，如不存在则记为Null。
"""
from business_rules import engine
from business_rules.actions import BaseActions, rule_action
from business_rules.variables import BaseVariables
from business_rules.variables import string_rule_variable
from business_rules.fields import FIELD_TEXT
from bson.objectid import ObjectId
import logging
import re
from pymongo import MongoClient

rule_info = {
    'span_level': 0,
    'CAPTCHA_phone': '',
    'binding_phone': '',
    'recipient_phone': '',
    'phone_number_in_address': '',
    'user_id': '',
}

MONGO_USER = MongoClient('mongodb://dataTask01:30001/db_prod', connect=False).db_prod
MONGO_BLACK_LIST = MongoClient('mongodb://dataTask01:30004/anti_fraud', connect=False).anti_fraud

FORMAT = '%(asctime)-15s %(levelname)s %(message)s'
logging.basicConfig(format=FORMAT, level=logging.INFO)


class address_variable(BaseVariables):
    def __init__(self, address_rule_info):
        self.rule_info = address_rule_info

    @string_rule_variable
    def binding_phone(self):
        return self.rule_info['binding_phone']

    @string_rule_variable
    def recipient_phone(self):
        return self.rule_info['recipient_phone']

    @string_rule_variable
    def phone_number_in_address(self):
        return self.rule_info['phone_number_in_address']

    @string_rule_variable
    def user_id(self):
        return self.rule_info['user_id']


class address_action(BaseActions):
    def __init__(self, address_rule_info):
        self.rule_info = address_rule_info

    @rule_action(params={"phone_number": FIELD_TEXT})
    def send_verification_code(self, phone_number):
        global rule_info
        rule_info['span_level'] = 1
        rule_info['CAPTCHA_phone'] = phone_number


def gen_rule():
    rules = [
        # 规则1 若A=spam_user，则判为suspicious，并往A发送验证码
        {
            'conditions': {'all': [
                {
                    'name': 'user_id',
                    'operator': 'equal_to',
                    'value': '' if MONGO_BLACK_LIST.antifraud_blacklist.find_one({
                        'type': 'user_id',
                        'content': rule_info['user_id']
                    }) is None else MONGO_BLACK_LIST.antifraud_blacklist.find_one({
                        'type': 'user_id',
                        'content': rule_info['user_id']
                    })['content'],
                }
            ]},
            'actions': [
                {
                    'name': 'send_verification_code',
                    'params': {'phone_number': rule_info['binding_phone']},
                }
            ]
        },
        # 规则2 若B!=Null and B!=C，则判为suspicious，并往C发送验证码
        {
            'conditions': {'all': [
                {
                    'name': 'phone_number_in_address',
                    'operator': 'not_equal_to',
                    'value': '',
                },
                {
                    'name': 'phone_number_in_address',
                    'operator': 'not_equal_to',
                    'value': rule_info['recipient_phone'],
                }
            ]},
            'actions': [
                {
                    'name': 'send_verification_code',
                    'params': {'phone_number': rule_info['recipient_phone']},
                }
            ]
        },
        # 规则3 若A!=Null and A!=C，则判为suspicious，并往A发送验证码
        {
            'conditions': {'all': [
                {
                    'name': 'binding_phone',
                    'operator': 'not_equal_to',
                    'value': '',
                },
                {
                    'name': 'binding_phone',
                    'operator': 'not_equal_to',
                    'value': rule_info['recipient_phone'],
                }
            ]},
            'actions': [
                {
                    'name': 'send_verification_code',
                    'params': {'phone_number': rule_info['binding_phone']},
                }
            ]
        },
    ]
    return rules


def get_rule_info(address_info):
    global rule_info
    # 获取用户收件人手机号
    rule_info['recipient_phone'] = address_info['recipient_phone']
    # 获取详细地址中的手机号
    address_detail = address_info['address_detail']
    resp = re.search(r'\D*(\d{13})?.*', address_detail)
    try:
        rule_info['phone_number_in_address'] = resp.group(1)
    except IndexError:
        rule_info['phone_number_in_address'] = ''
    # 获取用户绑定手机号和用户ID
    rule_info['user_id'] = address_info['user_id']
    user_info = MONGO_USER.user.find_one({
        '_id': ObjectId(rule_info['user_id'])
    })
    try:
        if user_info is None:
            logging.info(u'该用户ID不存在!')
            rule_info['binding_phone'] = ''
        else:
            rule_info['binding_phone'] = user_info['phone_info']['phone']
    except KeyError:
        rule_info['binding_phone'] = ''
        logging.info(u'该用户没有绑定手机号, user_id=%s' % rule_info['user_id'])


def run_address_rule(address_info):
    global rule_info
    # 清空上次保留的数据
    rule_info = {
        'span_level': 0,
        'CAPTCHA_phone': '',
        'binding_phone': '',
        'recipient_phone': '',
        'phone_number_in_address': '',
        'user_id': '',
    }
    # 提取rule规则所要的信息
    get_rule_info(address_info)
    result = engine.run_all(rule_list=gen_rule(),
                            defined_variables=address_variable(rule_info),
                            defined_actions=address_action(rule_info),
                            )

    return {
        'spam_level': rule_info['span_level'],
        'CAPTCHA_phone': rule_info['CAPTCHA_phone'],
    }
