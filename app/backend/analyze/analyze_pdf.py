import sys
import os
import argparse
import re

if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def analyze_pdf(filepath):
    if not os.path.exists(filepath):
        print(f"[오류] 파일을 찾을 수 없습니다: {filepath}")
        return

    print("=" * 60)
    print(f"PDF 악성 의심 키워드 스캔: {os.path.basename(filepath)}")
    print("=" * 60)

    suspicious_keywords = {
        b'/JS': 'JavaScript 코드 실행 가능성',
        b'/JavaScript': 'JavaScript 코드 내장',
        b'/AA': 'Automatic Action (페이지 열람 시 자동 실행)',
        b'/OpenAction': '문서 열람 시 자동 실행',
        b'/Launch': '외부 프로그램 실행 시도',
        b'/URI': '외부 웹사이트 연결 시도',
        b'/SubmitForm': '폼 데이터 전송 (피싱 가능성)',
        b'/RichMedia': '플래시 등 외부 미디어 포함',
        b'/ObjStm': 'Object Stream (내용을 숨기기 위해 사용될 수 있음)'
    }

    try:
        with open(filepath, 'rb') as f:
            content = f.read()

        print("\n[스캔 결과]")
        print(f"  {'키워드':<15} | {'발견 횟수':<10} | {'설명'}")
        print("-" * 70)

        risk_score = 0
        found_keywords = []
        
        for keyword, desc in suspicious_keywords.items():
            count = content.count(keyword)
            if count > 0:
                print(f"  {keyword.decode():<15} | {count:<10} | {desc}")
                found_keywords.append((keyword.decode(), count, desc))
                if keyword in [b'/JS', b'/JavaScript', b'/OpenAction', b'/Launch']:
                    risk_score += (count * 2)
                else:
                    risk_score += count

        if not found_keywords:
            print("  -> 의심스러운 키워드가 발견되지 않았습니다.")

        print("\n[종합 판정]")
        if risk_score == 0:
            print("  [클린] 의심스러운 키워드가 발견되지 않았습니다.")
        elif risk_score < 3:
            print("  [주의] 일부 스크립트나 액션이 포함되어 있습니다. (정상 문서일 수도 있음)")
        else:
            print("  [위험] 다수의 자동 실행 및 스크립트 요소가 발견되었습니다. 악성 가능성이 있습니다.")

    except Exception as e:
        print(f"[오류] 파일 읽기 실패: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PDF 악성 키워드 스캐너")
    parser.add_argument("filepath", help="분석할 PDF 파일 경로")
    args = parser.parse_args()
    analyze_pdf(args.filepath)