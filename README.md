# Quasar-RAT-Analysis-and-Suricata-based-Detection-Rule-Development
악성 프로그램(Quasar RAT) 분석 및 Suricata 기반 탐지 규칙 작성 및 시현

# Quasar RAT 1.3.0 (1.4.1) - RAT 패킷 분석 및 탐지

# What is QuasarRAT

1. RAT (Remote Access Trojan)중 하나인 Quasar은  DLL 사이드 로딩을 활용하여 레이더를 피해 감염된 Windows 호스트에서 은밀하게 데이터를 빼내는 특징이 존재.
2. 시스템 정보, 실행 중인 애플리케이션 목록, 파일, 키 입력, 스크린샷 및 임의의 셸 명령 실행을 수집할 수 있는 C# 기반 원격 관리 도구
3. GitHub 사용자 MaxXor가 작성하였으며, 현재까지 GitHub 저장소를 통해 공개적으로 호스팅중
4. 북한의  Kimsuky 공격 그룹에서  Quasar RAT기반의 오픈소스 RAT인    xRAT 악성코드를 사용하는 정황 포착
5. 사설 HTS위장을 통해 QuasarRAT 가 유출되고 있음
6. APT33, APT10, Dropping Elephant, Stone Panda, The Gorgon Group을 포함한 많은 실제 해킹 그룹이 Quasar RAT를 사용함

🔴 **중요**  
> QuasarRAT는 실제 공격에서도 자주 관측되는 툴로, 다양한 파생 버전이 존재.

![image](https://github.com/user-attachments/assets/ef6195ff-0d86-4df9-b34a-fc7721ec41dc)

## 요약 분석
### 프로그램 명 : QuasarRAT
### 프로그램 유형 : 원격제어
### 동작방식 : Server <-> Client
### 동작 os

```
├─ • Windows 11
├─ • Windows Server 2022
├─ • Windows Server 2019
├─ • Windows Server 2016
├─ • Windows 8/8.1
├─ • Windows Server 2012
├─ • Windows 10    
├─ • Windows Server 2008 R2
└─ • Windows 7      
```

## 관련 기술

1. BackDoor : 백도어는 공격자가 인증 절차를 우회하거나 몰래 시스템에 지속적인 접근 권한을 확보하기 위해 설치하는 악성 코드 또는 기능으로 흔히 RAT의 형태로 구현
2. DLL Side-Loading : DLL 사이드 로딩은 공격자가 정상 실행파일이 잘못된 경로의 DLL을 로드하도록 유도하여, 악성 DLL이 실행되게 하는 공격 기법
3. Process Hollowing : 프로세스 할로윙은 공격자가 정상 프로세스를 생성한 뒤, 해당 프로세스의 메모리를 비우고 악성 코드를 삽입하는 기법이다. 이로 인해 외부에서는 정상 프로세스처럼 보이지만, 내부에서는 악성코드가 실행

## 실행 흐름

![image](https://github.com/user-attachments/assets/ad320200-4cc5-42bf-8c17-2c9e319a2fae)

## 테스트 환경

+---------------------------------------------------------------------------------------------------------------+
| 🖥️ C2 Server (Windows 10)      | 🖥️ Agent (Windows 10)          | 🐧 Linux_Suricata (Ubuntu 20.04)  | 🖥️ Agent (Windows 7)           |
|--------------------------------|--------------------------------|----------------------------------|-------------------------------|
| RAT 실행 및 Agent 생성, 조작     | RAT 실행 및 Agent 생성, 조작   | Suricata 탐지 룰 작성             | RAT 실행 및 Agent 생성, 조작   |
|                                |                                |                                  |                               |
| [# C2 Server]  [# RAT]         | [# Agent]     [# Victim]       | [# 공격 탐지]   [# 룰작성]         | [# Agent]     [# Victim]       |
+---------------------------------------------------------------------------------------------------------------+





