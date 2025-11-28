# AWS 3-Tier Architecture 상세 문서

이 문서는 Virus Detector 프로젝트의 AWS 배포 구조를 상세하게 설명합니다.  
본 아키텍처는 확장성, 보안, 고가용성을 모두 만족하는 구조로 설계되었습니다.

---

# 1) 전체 흐름(Flow)

User
↓
Route53
↓
CloudFront (CDN, HTTPS)
↓
S3 (Frontend Static Files)
↓
External ALB (Public Load Balancer)
↓
Web Tier (Nginx Reverse Proxy - AZ-A, AZ-C)
↓
Internal ALB (Private Load Balancer)
↓
App Tier (Backend Auto Scaling Group)
↓
RDS (Database)

yaml
코드 복사

---

# 2) 구성 요소 상세 설명

## 🟦 CloudFront + S3
- 정적 파일을 전 세계 CDN을 통해 빠르게 제공
- S3는 프론트엔드 빌드 결과물만 저장
- CloudFront에서 HTTPS 종료(SSL Offloading)

---

## 🟩 Web Tier (Public Subnet)
- External ALB 뒤에서 동작
- Web EC2는 2개(AZ-A, AZ-C)
- 역할: Nginx Reverse Proxy
- `/api/*` 요청을 Internal ALB로 전달
- 프론트엔드 파일은 CloudFront가 담당하므로 Web EC2에서는 처리 X

---

## 🟧 Application Tier (Private Subnet)
- Backend(FastAPI/Flask) 서버
- Auto Scaling Group(ASG)로 구성
- Internal ALB를 통해 분산처리
- 실제 비즈니스 로직 처리, 파일 분석, DB 연동 담당

---

## 🟨 Database Tier (Private Subnet)
- RDS(MySQL/PostgreSQL)
- Backend 서버만 접근하도록 보안그룹 설정
- 자동 백업, Multi-AZ 가능

---

## 🟫 Network 구성
- VPC 1개
- Subnet 총 6개  
  - Public Subnet 2개  
  - Private App Subnet 2개  
  - Private DB Subnet 2개  
- NAT Gateway (Private → 인터넷 update 용)
- Internet Gateway (Public → 인터넷 연결)

---

# 3) Security Group 구조

SG-External-ALB
↓ allows
SG-Web (Nginx EC2)
↓ allows
SG-Internal-ALB
↓ allows
SG-App (Backend)
↓ allows
SG-RDS

pgsql
코드 복사

이 구조는 Zero-Trust 목표로 설계됨.

---

# 4) 향후 개선/확장 포인트
- S3 버킷 정책 강화 (Origin Access Control)
- App Tier에 CI/CD 구축 (Github Actions)
- RDS Multi-AZ 및 Read Replica 추가
- ALB Logging & CloudWatch Monitoring 추가