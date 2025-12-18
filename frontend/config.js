// SafeScan API 설정
const CONFIG = {
  // API Base URL - Internal ALB는 CloudFront를 통해 라우팅
  API_BASE_URL: (() => {
    const hostname = window.location.hostname;
    
    // 로컬 개발 환경
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
      return 'http://localhost:8000';
    }
    
    // 프로덕션 환경 (CloudFront)
    // CloudFront가 /scan/*, /auth/*, /api/* 등을 Internal ALB로 라우팅
    return '';  // 같은 도메인 사용
  })(),
  
  // CloudFront 도메인
  CLOUDFRONT_DOMAIN: 'https://d2atpnajyyx47s.cloudfront.net'
};

console.log('SafeScan Config:', CONFIG);