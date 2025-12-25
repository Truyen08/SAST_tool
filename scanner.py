import sys, os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


import json
import subprocess
import ast
import os
from datetime import datetime
from rules.ast_rules import ALL_RULES



def scan_with_bandit(target_path: str):
    """
    Scan bằng Bandit.
    - Nếu target_path là file .py → quét file.
    - Nếu target_path là thư mục → quét toàn bộ mã nguồn trong folder.
    """
    cmd = ["bandit", "-f", "json"]

    if os.path.isfile(target_path) and target_path.endswith(".py"):
        cmd += ["-r", os.path.dirname(target_path), "-ll"]      # lọc từ medium trở lên
    elif os.path.isdir(target_path):
        cmd += ["-r", target_path, "-ll"]
    else:
        print("Không phải file .py hoặc thư mục hợp lệ")
        return None

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)    #gọi bandit qua subprocess
        return json.loads(result.stdout)
    except Exception as e:
        print("Lỗi khi chạy Bandit:", e)
        return None


# Scan bằng AST
class ASTAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.tree = None

    def load(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            self.tree = ast.parse(f.read())     #phân tích mã python thành AST

    def analyze(self):
        findings = []

        for node in ast.walk(self.tree):        #duyệt qua các node trong AST
            for rule in ALL_RULES:
                result = rule.check(node)
                if result:
                    findings.append(result)
        return findings



# Xuất kết quả ra JSON/HTML
def export_report(bandit_result, ast_result, output_type="json"):
    if not os.path.exists("logged"):
        os.mkdir("logged")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Chuyển đổi kết quả Bandit sang định dạng mong muốn nếu là dict
    bandit_items = []
    if isinstance(bandit_result, dict) and "results" in bandit_result:
        for item in bandit_result["results"]:
            bandit_items.append({
                "ten_loi": item.get("test_name", "N/A"),
                "muc_do": item.get("issue_severity", "N/A"),
                "dong": item.get("line_number", "N/A"),
                "mo_ta": item.get("issue_text", "")
            })
    elif isinstance(bandit_result, list):
        bandit_items = bandit_result
    else:
        bandit_items = []

    report = {
        "thoi_gian_quet": timestamp,
        "bandit": bandit_items,
        "ast": ast_result
    }

    if output_type == "json":
        file_path = f"logged/report_{timestamp}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

    elif output_type == "html":
        file_path = f"logged/report_{timestamp}.html"
        html = "<html><body><h1>Kết quả quét mã</h1>"
        html += f"<p>Thời gian: {timestamp}</p>"

        html += "<h2>Bandit</h2><ul>"
        for item in report["bandit"]:
            html += f"<li><b>{item.get('ten_loi', 'N/A')}</b> – {item.get('muc_do', 'N/A')} – dòng {item.get('dong', 'N/A')}<br>{item.get('mo_ta', '')}</li>"
        html += "</ul>"

        html += "<h2>AST</h2><ul>"
        for item in report["ast"]:
            html += f"<li><b>{item.get('message', 'N/A')}</b> – {item.get('type', 'N/A')} – dòng {item.get('line', 'N/A')}</li>"
        html += "</ul></body></html>"

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html)

    print(f"Đã xuất báo cáo: {file_path}")




# Hàm chạy scan để CLI gọi
def run_scan(target_path: str, output_type: str = "json", use_bandit: bool = True, use_ast: bool = True):
    """
    Giữ nguyên logic cũ nhưng cho phép CLI truyền tham số:
    - target_path: file .py hoặc thư mục
    - output_type: json/html
    - use_bandit/use_ast: bật/tắt từng engine
    """
    bandit_result = None
    ast_result = []

    if use_bandit:
        print("=== Quét bằng Bandit ===")
        bandit_result = scan_with_bandit(target_path)
    else:
        print("=== Bandit: OFF ===")

    if use_ast:
        print("\n=== Quét bằng AST ===")
        # Nếu target là folder -> quét tất cả *.py trong folder
        files_to_scan = []
        if os.path.isfile(target_path) and target_path.endswith(".py"):
            files_to_scan = [target_path]
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for fn in files:
                    if fn.endswith(".py"):
                        files_to_scan.append(os.path.join(root, fn))
        else:
            print("Target không hợp lệ cho AST")
            files_to_scan = []

        for fp in files_to_scan:
            analyzer = ASTAnalyzer(fp)
            try:
                analyzer.load()
                findings = analyzer.analyze()
                # thêm file vào finding để report rõ
                for item in findings:
                    item.setdefault("file", fp)
                ast_result.extend(findings)
            except SyntaxError as e:
                ast_result.append({
                    "type": "Info",
                    "message": f"Không parse được file (SyntaxError): {e}",
                    "line": "N/A",
                    "file": fp
                })
            except Exception as e:
                ast_result.append({
                    "type": "Info",
                    "message": f"Không quét được file: {e}",
                    "line": "N/A",
                    "file": fp
                })
    else:
        print("=== AST: OFF ===")

    export_report(bandit_result, ast_result, output_type=output_type)
    return bandit_result, ast_result





# Chương trình chính
if __name__ == "__main__":
    file_to_scan = "test.py"

    print("=== Quét bằng Bandit ===")
    bandit_result = scan_with_bandit(file_to_scan)

    print("\n=== Quét bằng AST ===")
    analyzer = ASTAnalyzer(file_to_scan)
    analyzer.load()
    ast_result = analyzer.analyze()

    # lưu báo cáo
    export_report(bandit_result, ast_result, output_type="json")
