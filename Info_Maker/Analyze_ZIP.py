import sys
import os
import argparse
import zipfile

def analyze_zip(filepath):
    if not os.path.exists(filepath):
        print(f"[오류] 파일을 찾을 수 없습니다: {filepath}")
        return

    if not zipfile.is_zipfile(filepath):
        print("[오류] 유효한 ZIP 파일이 아닙니다.")
        return

    print("=" * 60)
    print(f"ZIP 압축 파일 구조 분석: {os.path.basename(filepath)}")
    print("=" * 60)

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            file_list = zf.infolist()
            print(f"  - 총 파일 개수: {len(file_list)}개")
            
            print("\n[내부 파일 상세 분석]")
            print(f"  {'파일명':<30} | {'압축률':<8} | {'상태'}")
            print("-" * 70)

            dangerous_exts = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.wsf', '.ps1']
            
            for info in file_list:
                # 1. 압축률 계산 (Zip Bomb 탐지)
                # compress_size가 0인 경우(빈 파일 등) 예외 처리
                ratio = 0
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                
                # 2. 파일명 디코딩 (한글 깨짐 방지 시도)
                try:
                    filename = info.filename.encode('cp437').decode('euc-kr')
                except:
                    filename = info.filename

                # 3. 위험 요소 탐지
                flags = []
                
                # Zip Bomb 체크: 압축률이 100배 이상이면 매우 의심
                if ratio > 100:
                    flags.append("💣ZipBomb의심")
                
                # 위험 확장자 체크
                ext = os.path.splitext(filename)[1].lower()
                if ext in dangerous_exts:
                    flags.append(f"🚨실행파일({ext})")
                
                # 암호화 여부 (Flag bit 0)
                if info.flag_bits & 0x1:
                    flags.append("🔒암호화됨")

                status_str = ", ".join(flags) if flags else "정상"
                
                # 출력 (파일명이 너무 길면 자르기)
                display_name = (filename[:27] + '..') if len(filename) > 27 else filename
                print(f"  {display_name:<30} | {ratio:.1f}x     | {status_str}")

    except zipfile.BadZipFile:
        print("[오류] 손상된 ZIP 파일입니다.")
    except Exception as e:
        print(f"[오류] 분석 중 예외 발생: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZIP 파일 보안 분석 도구")
    parser.add_argument("filepath", help="분석할 ZIP 파일 경로")
    args = parser.parse_args()
    analyze_zip(args.filepath)
