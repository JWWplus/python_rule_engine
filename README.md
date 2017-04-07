## 使用前提
运行 pip install -r requirements.txt

会安装python扩展引擎包, 修改operators.py文件  将如下代码加入到
class StringType 这个类中。

    @type_operator(FIELD_TEXT)
    def not_equal_to(self, other_string):
        return not(self.value == other_string)

## 现在实现的新建地址规则:
从该账户下绑定的手机号、收件地址中包含的手机号、收件人手机号三处提取手机号，分别记为A、B、C，如不存在则记为Null.

1. 若B!=Null and B!=C，则判为suspicious，并往C发送验证码
2. 若A!=Null and A!=C，则判为suspicious，并往A发送验证码
3. 若A=spam_user，则判为suspicious，并往A发送验证码
4. 其余情况均属正常，不判为spam



**api以json格式返回**
1. spam_level：1/0
2. CAPTCHA_phone：需要发验证码的手机




