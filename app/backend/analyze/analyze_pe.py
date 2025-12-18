import sys
import os
import argparse

try:
    import pefile
except ImportError:
    print("[오류] 'pefile' 라이브러리가 필요합니다. 설치: pip install pefile")
    sys.exit(1)

def analyze_pe(filepath):
    if not os.path.exists(filepath):
        print(f"[오류] 파일을 찾을 수 없습니다: {filepath}")
        return

    print("=" * 60)
    print(f"PE (EXE/DLL) 정적 분석 시작: {os.path.basename(filepath)}")
    print("=" * 60)

    try:
        pe = pefile.PE(filepath)

        # 1. 기본 헤더 정보
        print("\n[1] 기본 정보 (Header Info)")
        print(f"  - Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"  - Image Base:  {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"  - 섹션 개수:   {pe.FILE_HEADER.NumberOfSections}")
        print(f"  - 컴파일 시간: {pe.FILE_HEADER.TimeDateStamp}")

        # 2. 섹션 정보 및 엔트로피 (패킹 탐지)
        print("\n[2] 섹션 정보 & 패킹 탐지 (Entropy)")
        print("  * 엔트로피가 7.0 이상이면 패킹(Packing) 또는 암호화 가능성이 높습니다.")
        print(f"  {'이름':<10} | {'크기(Raw)':<10} | {'엔트로피':<10} | {'상태'}")
        print("-" * 60)
        
        for section in pe.sections:
            entropy = section.get_entropy()
            name = section.Name.decode('utf-8', 'ignore').strip().replace('\x00', '')
            raw_size = section.SizeOfRawData
            
            status = ""
            if entropy > 7.0:
                status = "🚨 의심 (패킹?)"
            elif raw_size == 0 and entropy < 1:
                status = "비어있음"
            
            print(f"  {name:<10} | {raw_size:<10} | {entropy:.4f}     | {status}")

        # 3. 의심스러운 API 호출 (Import Table)
        print("\n[3] 주요 의심 API 호출 (Import Table)")
        suspicious_apis = [
            'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', # 메모리 조작/인젝션
            'ShellExecute', 'WinExec', 'CreateProcess',                 # 프로세스 실행
            'URLDownloadToFile', 'InternetOpen',                        # 네트워크 연결
            'RegOpenKey', 'RegSetValue'                                 # 레지스트리 조작
        ]
        
        found_apis = False
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore')
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', 'ignore')
                        # 의심 리스트에 포함되거나, 비슷하면 출력
                        if any(api in func_name for api in suspicious_apis):
                            print(f"  🚨 탐지됨: {func_name:<25} (라이브러리: {dll_name})")
                            found_apis = True
        else:
            print("  -> 임포트 테이블이 없습니다. (패킹되어 있을 확률이 매우 높음)")

        if not found_apis:
            print("  -> 특이한 악성 API가 명시적으로 발견되지 않았습니다.")

    except pefile.PEFormatError:
        print("[오류] 유효한 PE 파일이 아닙니다.")
    except Exception as e:
        print(f"[오류] 분석 중 예외 발생: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PE(EXE) 파일 정적 분석 도구")
    parser.add_argument("filepath", help="분석할 EXE/DLL 파일 경로")
    args = parser.parse_args()
    analyze_pe(args.filepath)