import sys
import os
import argparse
import subprocess # 명령줄 도구 실행용
import olefile    # olemeta 대체 및 olefile 라이브러리 직접 사용
from oletools import oleid
from oletools import olevba

# --- [1] 명령줄 도구 실행 헬퍼 ---
def run_command_tool(command_name, filepath):
    """
    oletools의 명령줄 도구(oledir, olemap 등)를 실행하고 원본 출력을 반환합니다.
    """
    # 시스템에 설치된 파이썬을 이용해 모듈로 실행 (경로 문제 방지)
    command = [sys.executable, "-m", f"oletools.{command_name}", filepath]
    
    try:
        # Popen을 사용하여 stdout/stderr을 모두 캡처
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            return f"  [오류] {command_name} 실행 실패:\n{stderr}"
        
        if not stdout.strip():
            return "  -> (출력 정보 없음)"
            
        return stdout.strip()

    except FileNotFoundError:
        return f"  [오류] {command_name}을(를) 찾을 수 없습니다. oletools가 올바르게 설치되었는지 확인하세요."
    except Exception as e:
        return f"  [오류] {command_name} 실행 중 예외 발생: {e}"

# --- [2] 라이브러리 도구 실행 (oleid) ---
def analyze_oleid(filepath):
    print("\n--- 1. oleid (파일 식별 및 위험 지표) ---")
    try:
        oid = oleid.OleID(filepath)
        indicators = oid.check()
        
        if not indicators:
            print("  -> OLE/Compound File 인디케이터 없음.")
            return

        for i in indicators:
            print(f"  - ID: {i.id}")
            print(f"    Name: {i.name}")
            print(f"    Value: {i.value}")
            print(f"    Description: {i.description}\n")

    except Exception as e:
        print(f"  [오류] oleid 분석 오류: {e}")

# --- [3] 라이브러리 도구 실행 (olemeta/olefile) ---
def analyze_metadata(filepath):
    print("\n--- 2. olemeta (메타데이터 요약) ---")
    print("   (olefile 라이브러리를 사용하여 SummaryInformation을 직접 파싱합니다)")
    try:
        if not olefile.isOleFile(filepath):
            print("  -> OLE 파일이 아니므로 메타데이터를 읽을 수 없습니다.")
            return

        ole = olefile.OleFileIO(filepath)
        
        # 'SummaryInformation' 스트림에서 속성 읽기
        if ole.exists('SummaryInformation'):
            props = ole.getproperties('SummaryInformation')
            print("\n  [SummaryInformation]")
            if not props:
                print("    -> 속성 정보 없음")
            for name, value in props.items():
                print(f"    - {name}: {value}")
        else:
            print("\n  [SummaryInformation] -> 스트림을 찾을 수 없음")

        # 'DocumentSummaryInformation' 스트림에서 속성 읽기
        if ole.exists('DocumentSummaryInformation'):
            props = ole.getproperties('DocumentSummaryInformation')
            print("\n  [DocumentSummaryInformation]")
            if not props:
                print("    -> 속성 정보 없음")
            for name, value in props.items():
                print(f"    - {name}: {value}")
        else:
            print("\n  [DocumentSummaryInformation] -> 스트림을 찾을 수 없음")
            
        ole.close()
    except Exception as e:
        print(f"  [오류] 메타데이터 분석 오류: {e}")

# --- [4] 라이브러리 도구 실행 (olevba) ---
def analyze_olevba(filepath):
    print("\n--- 3. olevba (VBA 매크로 분석) ---")
    
    # HWP 파일은 VBA를 사용하지 않으므로 건너뛰기
    if filepath.lower().endswith('.hwp'):
        print("  -> HWP 파일입니다. VBA 매크로 분석을 건너뜁니다.")
        return
        
    vba_parser = None
    try:
        vba_parser = olevba.VBA_Parser(filepath)
        
        if vba_parser.detect_vba_macros():
            print("  🚨 **매크로 탐지: VBA 코드가 파일에 존재합니다.**\n")
            
            # 모든 매크로 스트림 정보 출력
            print("  [매크로 스트림 정보]")
            for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                print(f"  - OLE 파일명: {filename}")
                print(f"    스트림 경로: {stream_path}")
                print(f"    VBA 모듈명: {vba_filename}")
                print(f"    코드 크기: {len(vba_code)} bytes\n")

            # 분석 결과 (의심 키워드, 자동 실행 등)
            print("  [매크로 코드 분석 결과]")
            analysis_results = vba_parser.analyze_macros()
            
            if not analysis_results:
                print("  -> 분석 결과 없음")
                
            for keyword, description, count in analysis_results:
                if count > 0: # 0이 아닌 결과만 출력
                    print(f"  - 키워드: {keyword}")
                    print(f"    설명: {description}")
                    print(f"    횟수: {count}\n")
        else:
            print("  -> VBA 매크로가 탐지되지 않았습니다.")
            
    except Exception as e:
        print(f"  [에러] olevba 분석 오류: {e}")
    finally:
        if vba_parser:
            vba_parser.close()

# --- [5] 메인 함수 (모든 분석기 실행) ---
def main_analysis(filepath):
    if not os.path.exists(filepath):
        print(f"[오류] 파일을 찾을 수 없습니다: {filepath}")
        return

    filename = os.path.basename(filepath)
    print("=" * 70)
    print(f"파일 전체 분석 시작: {filename}")
    print("=" * 70)

    # 1. oleid (라이브러리)
    analyze_oleid(filepath)
    
    # 2. olemeta / olefile (라이브러리)
    analyze_metadata(filepath)

    # 3. olevba (라이브러리)
    analyze_olevba(filepath)

    # 4. oledir (명령줄)
    print("\n--- 4. oledir (OLE 디렉토리 구조) ---")
    print(run_command_tool("oledir", filepath))

    # 5. olemap (명령줄)
    print("\n--- 5. olemap (OLE 섹터 맵) ---")
    print(run_command_tool("olemap", filepath))
    
    # 6. oletimes (명령줄)
    print("\n--- 6. oletimes (스트림 타임스탬프) ---")
    print(run_command_tool("oletimes", filepath))

    # 7. oleobj (명령줄)
    print("\n--- 7. oleobj (임베디드 OLE 객체) ---")
    print(run_command_tool("oleobj", filepath))

    print("\n" + "=" * 70)
    print(f"파일 분석 완료: {filename}")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="oletools를 이용한 MS/HWP 파일 상세 정보 분석")
    parser.add_argument("filepath", help="분석할 파일의 경로")
    
    args = parser.parse_args()
    
    main_analysis(args.filepath)