import ast
import re

class BaseRule:
    """Base class cho tất cả rule."""
    def check(self, node):
        raise NotImplementedError



# RULE 1 – Phát hiện eval(), exec()
class DangerousEvalRule(BaseRule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ["eval", "exec"]:
                return {
                    "type": "High",
                    "message": f"Dùng {node.func.id}() – nguy cơ RCE",
                    "line": node.lineno
                }



# RULE 2 – subprocess(..., shell=True)
class SubprocessShellRule(BaseRule):
    def check(self, node):
        if isinstance(node, ast.Call):
            # Tên hàm là subprocess
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ["Popen", "call", "run"]:
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            return {
                                "type": "High",
                                "message": "subprocess với shell=True – Command Injection",
                                "line": node.lineno
                            }



# RULE 3 – os.system()
class OsSystemRule(BaseRule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "system":
                return {
                    "type": "Medium",
                    "message": "os.system() – dễ dẫn đến Command Injection",
                    "line": node.lineno
                }



# RULE 4 – pickle.load() / pickle.loads()
class PickleRule(BaseRule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ["load", "loads"]:
                return {
                    "type": "High",
                    "message": "Dùng pickle.load() – dễ RCE nếu dữ liệu không trust",
                    "line": node.lineno
                }



# RULE 5 – yaml.load() không có SafeLoader
class YamlUnsafeLoadRule(BaseRule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "load":
                return {
                    "type": "High",
                    "message": "yaml.load() không dùng SafeLoader – rất nguy hiểm",
                    "line": node.lineno
                }



# RULE 6 – Hardcoded password / key / token
class HardcodedSecretsRule(BaseRule):
    SECRET_PATTERN = re.compile(r"(password|passwd|pwd|secret|token|apikey|api_key)", re.IGNORECASE)

    def check(self, node):
        # Detect variable = "something"
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if self.SECRET_PATTERN.search(target.id):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            return {
                                "type": "High",
                                "message": f"Hardcoded secret trong biến '{target.id}'",
                                "line": node.lineno
                            }


# RULE 7 – requests.get(..., verify=False)
class RequestsVerifyFalseRule(BaseRule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ["get", "post", "put", "delete"]:
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        return {
                            "type": "Medium",
                            "message": "requests.*() với verify=False → Bypass SSL",
                            "line": node.lineno
                        }



# RULE 8 – hashlib.md5/sha1 (yếu)
class WeakHashRule(BaseRule):
    weak_algorithms = ["md5", "sha1"]

    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr.lower() in self.weak_algorithms:
                return {
                    "type": "Medium",
                    "message": f"Dùng thuật toán hash yếu: {node.func.attr}",
                    "line": node.lineno
                }



# RULE 9 – os.popen()
class OsPopenRule(BaseRule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "popen":
                return {
                    "type": "Medium",
                    "message": "os.popen() – dễ dẫn đến Command Injection",
                    "line": node.lineno
                }


# RULE 10 – tempfile.mktemp() (TOCTOU, race condition)
class InsecureTempfileMktempRule(BaseRule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "mktemp":
                return {
                    "type": "Medium",
                    "message": "tempfile.mktemp() – không an toàn (TOCTOU). Dùng NamedTemporaryFile/mkstemp",
                    "line": node.lineno
                }


# RULE 11 – SQL injection: execute() với string format (% / f-string / .format)
class SqlInjectionExecuteRule(BaseRule):
    def _is_dynamic_sql(self, arg):
        # "SELECT ... %s" % user
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
            return True
        # f"SELECT ... {user}"
        if isinstance(arg, ast.JoinedStr):
            return True
        # "SELECT ... {}".format(user)
        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
            return True
        return False

    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ["execute", "executemany"]:
                if node.args:
                    if self._is_dynamic_sql(node.args[0]):
                        return {
                            "type": "High",
                            "message": "cursor.execute() với dynamic SQL (f-string/%/.format) – nguy cơ SQL Injection. Dùng parameterized query",
                            "line": node.lineno
                        }


# RULE 12 – Flask debug=True (production risk)
class FlaskDebugTrueRule(BaseRule):
    def check(self, node):
        # app.run(debug=True)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "run":
                for kw in node.keywords:
                    if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        return {
                            "type": "Medium",
                            "message": "Flask app.run(debug=True) – rủi ro lộ thông tin/console debug",
                            "line": node.lineno
                        }
        # app.debug = True
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == "debug":
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        return {
                            "type": "Medium",
                            "message": "Flask app.debug = True – không nên bật ở production",
                            "line": node.lineno
                        }


# RULE 13 – Django DEBUG=True
class DjangoDebugTrueRule(BaseRule):
    def check(self, node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEBUG":
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        return {
                            "type": "Medium",
                            "message": "Django DEBUG=True – rủi ro lộ thông tin nhạy cảm khi lỗi",
                            "line": node.lineno
                        }


# RULE 14 – PyJWT: jwt.decode(..., options={'verify_signature': False})
class JwtDecodeNoVerifyRule(BaseRule):
    def check(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # jwt.decode(...)
            if node.func.attr == "decode":
                for kw in node.keywords:
                    if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                        keys = kw.value.keys
                        vals = kw.value.values
                        for k, v in zip(keys, vals):
                            if isinstance(k, ast.Constant) and k.value == "verify_signature":
                                if isinstance(v, ast.Constant) and v.value is False:
                                    return {
                                        "type": "High",
                                        "message": "jwt.decode() tắt verify_signature – có thể bypass xác thực JWT",
                                        "line": node.lineno
                                    }


# RULE 15 – Paramiko: AutoAddPolicy (MITM risk)
class ParamikoAutoAddPolicyRule(BaseRule):
    def check(self, node):
        # client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "set_missing_host_key_policy" and node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Call) and isinstance(arg0.func, ast.Attribute):
                    if arg0.func.attr == "AutoAddPolicy":
                        return {
                            "type": "Medium",
                            "message": "Paramiko AutoAddPolicy – tự động trust host key (rủi ro MITM). Nên pin host key/RejectPolicy",
                            "line": node.lineno
                        }


# RULE 16 – random dùng để tạo token/secret/key (không phù hợp crypto)
class InsecureRandomForSecretsRule(BaseRule):
    SECRET_NAME = re.compile(r"(token|secret|apikey|api_key|key|session)", re.IGNORECASE)

    def check(self, node):
        # token = random.random()/randint()/choice()...
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            val = node.value
            if isinstance(val.func, ast.Attribute):
                if val.func.attr in ["random", "randint", "choice", "choices"]:
                    # random.<...>
                    base = val.func.value
                    if isinstance(base, ast.Name) and base.id == "random":
                        for target in node.targets:
                            if isinstance(target, ast.Name) and self.SECRET_NAME.search(target.id):
                                return {
                                    "type": "Low",
                                    "message": f"Dùng random để tạo '{target.id}' – không an toàn cho mục đích bảo mật. Dùng secrets module",
                                    "line": node.lineno
                                }


# DANH SÁCH TẤT CẢ RULE
ALL_RULES = [
    DangerousEvalRule(),
    SubprocessShellRule(),
    OsSystemRule(),
    PickleRule(),
    YamlUnsafeLoadRule(),
    HardcodedSecretsRule(),
    RequestsVerifyFalseRule(),
    WeakHashRule(),

    OsPopenRule(),
    InsecureTempfileMktempRule(),
    SqlInjectionExecuteRule(),
    FlaskDebugTrueRule(),
    DjangoDebugTrueRule(),
    JwtDecodeNoVerifyRule(),
    ParamikoAutoAddPolicyRule(),
    InsecureRandomForSecretsRule(),
]