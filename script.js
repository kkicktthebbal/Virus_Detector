const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const scanBtn = document.getElementById('scanBtn');
const llmSummary = document.getElementById('llmSummary');
const jsonResult = document.getElementById('jsonResult');

fileInput.addEventListener('change', () => {
  fileName.textContent = fileInput.files.length > 0 
    ? fileInput.files[0].name 
    : '선택된 파일 없음';
});

scanBtn.addEventListener('click', () => {
  if (!fileInput.files.length) {
    alert('파일을 먼저 선택해주세요!');
    return;
  }

  // 예시용 더미 결과
  llmSummary.value = '이 파일은 의심스러운 실행 파일로 보입니다. 주요 행위는 네트워크 연결 및 레지스트리 수정입니다.';
  
  const sampleJSON = {
    fileName: fileInput.files[0].name,
    detected: true,
    riskLevel: "High",
    behavior: ["Network connection", "Registry modification"],
    sha256: "a1b2c3d4e5f6..."
  };

  jsonResult.value = JSON.stringify(sampleJSON, null, 2);
});
