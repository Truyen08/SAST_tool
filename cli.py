import argparse
import os
import sys

from scanner import run_scan

def main():
    # parser = argparse.ArgumentParser(description="CLI - Python Static Scanner (Bandit + AST)")
    parser = argparse.ArgumentParser(
    description=(
        "Python Static Security Scanner\n"
        "- Quét mã nguồn Python bằng Bandit và AST custom rules\n"
        "- Hỗ trợ quét file hoặc toàn bộ thư mục"
    ),
    epilog=(
        "Ví dụ sử dụng:\n"
        "  python cli.py                      # Quét file mặc định test.py\n"
        "  python cli.py <tên file>              # Quét 1 file cụ thể\n"
        "  python cli.py ./src                # Quét toàn bộ thư mục src\n"
        "  python cli.py ./src -o html        # Xuất báo cáo HTML\n"
        "  python cli.py ./src --no-bandit    # Chỉ quét AST rules\n"
        "  python cli.py ./src --no-ast       # Chỉ quét Bandit\n"
        "\n"
        "Lưu ý:\n"
        "- Kết quả được lưu trong thư mục logged/\n"
    ),
    formatter_class=argparse.RawTextHelpFormatter
)



    parser.add_argument("target", nargs="?", default="test.py",
                        help="Đường dẫn file .py hoặc thư mục cần quét (mặc định: test.py)")
    parser.add_argument("-o", "--output", choices=["json", "html"], default="json",
                        help="Định dạng report")
    parser.add_argument("--no-bandit", action="store_true", help="Tắt Bandit")
    parser.add_argument("--no-ast", action="store_true", help="Tắt AST rules")
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print("[!] Target không tồn tại:", args.target)
        sys.exit(1)

    run_scan(
        target_path=args.target,
        output_type=args.output,
        use_bandit=not args.no_bandit,
        use_ast=not args.no_ast
    )

if __name__ == "__main__":
    main()