![image](https://github.com/user-attachments/assets/fceeb371-ac37-438c-bd95-616802c3c8c1)![image](https://github.com/user-attachments/assets/6c826d68-1b32-416a-a1a4-9464c2e3e582)![image](https://github.com/user-attachments/assets/8766ccc7-e6a2-4d09-a8a6-be784cece094)![image](https://github.com/user-attachments/assets/75613fbd-218f-4825-b4df-d3cd84194a0f)![image](https://github.com/user-attachments/assets/64f55b89-de65-4c49-a4b0-2224214dc435)![image](https://github.com/user-attachments/assets/f229e9ad-6762-4acb-a1d4-1097533cef25)![image](https://github.com/user-attachments/assets/b7932bd5-4c99-4bb7-9659-36c2c9cf247d)![image](https://github.com/user-attachments/assets/5691310d-4f83-440f-9e07-84a6c8d59c3c)![image](https://github.com/user-attachments/assets/6b4f2364-bc4e-4372-a3ae-f660fdc762ff)![image](https://github.com/user-attachments/assets/38eb2776-2123-470d-ad64-c72c7851fd34)# Quasar-RAT-Analysis-and-Suricata-based-Detection-Rule-Development
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

```
[C2 Server]  🖥️                 [Linux IDS: Suricata] 🐧                   🖥️  [Client Victim]
    │                                      │                                      │
    │ <========= 2. 연결 수락 ============ │ <========= 1. TCP 연결 요청 ======== │
    │                                      │                                      │
    │ ==========> 3. 명령어 전달 =========>│                                      │
```

## 테스트 절차
1. Server(C2) 시스템에 설치된 RAT프로그램을 통한 Agent 감염 파일 생성
2. Victim PC 에 Agent 프로그램 복사 및 실행
3. Server(C2) 시스템에서 RAT 프로그램을 통해 다양한 공격 실행 
4. 와이어 샤크를 통한 패킷 캡처 후 초기 연결 부터 데이터 전송 연결유지 패킷 탐색 
5. Suricata Detection Rule 작성

## Quasar RAT Client Builder 설정 흐름 정리

![image](https://github.com/user-attachments/assets/012ee1d7-c53d-4a33-9fe3-340e3e8d83ec)
1. Quasar RAT 실행시 상단 4개 툴바 존재
2. Settings -> C2_Server에서  리스닝할 포트 지정 가능
3. 일반적으로 RAT 서버 설정에서 사용
4. 포트 열고 클라이언트의 연결 수신
5. 외부 접속 허용 시 포트 포워딩 설정 포함
6. 클라이언트와 통신 시 사용할 인증 비밀번호

![image](https://github.com/user-attachments/assets/2b49142c-c10c-46c3-b2c0-4138560a33ac)
###  기본 설정 (Basic Settings)
- Client Tag 및 접속 포트 설정  
  예시: `User@PC`, Port: `4782`

---

### 연결 설정 (Connection Settings)
- C2 서버와 통신 시 사용할 **인증 비밀번호 설정**
- 클라이언트와 통신 시 사용할 인증 비밀번호

---

### 설치 설정 (Installation Settings)
- 클라이언트 실행 시 지정 경로에 복사되도록 설정
- 설치 위치 선택:
  - User Application Data / Program Files / System
- 하위 폴더 및 파일 이름 지정: `SubDir\Client.exe`
- 파일/폴더 속성을 숨김으로 설정
- 시스템 시작 시 자동 실행 등록 (`Quasar Client Startup`)

📌 설치 경로 예시: C:\Users\g2h\AppData\Roaming\SubDir\Client.exe
---

## 4️⃣ 어셈블리 설정 (Assembly Settings)
- 실행 파일의 메타데이터 수정 가능:
  - Product Name, Company, Version 등
- 실행 파일 아이콘 변경 가능
  - 정상 프로그램으로 위장 가능

---

## 5️⃣ 감시 설정 (Surveillance Settings)
- 키로깅 기능 활성화 가능
- 로그 저장 디렉토리 지정 (`Logs`)
- 로그 폴더 숨김 설정 가능

---

## 6️⃣ Build Client
- 모든 설정 완료 후 **빌드 버튼 클릭** 시 `.exe` 생성
- 해당 Agent 파일이 실제 공격에 사용됨

---

[Basic Settings] ↓ [Connection Settings] ↓ [Installation Settings] ↓ [Assembly Settings] ↓ [Surveillance Settings] ↓ ▶ Build Client (.exe 생성)


| 설정 구간              | 공격자 목적                        | 보안 대응 관점                                               |
|------------------------|------------------------------------|--------------------------------------------------------------|
| 🔐 Connection Settings | 인증 우회 방지                    | 고정된 비밀번호 사용 탐지, Suricata 룰 적용 가능             |
| 📁 Installation Settings | 파일 은닉 및 자동 실행             | 경로 기반 탐지, 파일/레지스트리 감시, Autorun 등록 확인     |
| 🧾 Assembly Settings    | 실행 파일 위장                     | 파일 메타데이터 및 아이콘 분석을 통한 위장 탐지              |
| 🎯 Surveillance Settings | 사용자 정보 수집 (키로깅)         | 로그 저장 경로 및 행위 기반 탐지, Keylogger 탐지 룰 적용     |

![image](https://github.com/user-attachments/assets/f422d95e-544d-43aa-8607-c9c9873e8e83)

![image](https://github.com/user-attachments/assets/59160cb9-4d3d-4650-86fc-c06143bc6198)

## 트래픽 분석

![image](https://github.com/user-attachments/assets/c2d6c496-b0d3-48ba-81f4-08f982daf8db)
<hr>
![image](https://github.com/user-attachments/assets/46539376-ec73-47af-af1c-b846b0334a4d)
<hr>
![image](https://github.com/user-attachments/assets/69025936-409b-4942-9109-57d4894f3444)
<hr>
![image](https://github.com/user-attachments/assets/461811ba-01b4-4950-ae12-c11a01a56d2b)
<hr>
![image](https://github.com/user-attachments/assets/e26c562a-759c-469e-b5b1-6ddbead7dd8c)

> TCP Steream 을 통해 패킷 데이터를 확인해보면, 암호화된 데이터로 출력되어,
실제 데이터 확인이 어려움
![image](https://github.com/user-attachments/assets/c8944d47-bb80-45ec-a223-d806e1dcef8d)<br>
![image](https://github.com/user-attachments/assets/74ee3a32-2b01-4a31-bc15-2847a66b49ca)
> 빌드시 자동생성되는 Client.bin 파일을 디컴파일 해본 결과 xClinent.Core.Cryptography  부분에 데이터를 암호화하는 AES, SHA256 파일이 존재, 이를통해 암호화 알고리즘을 식별 할 수 있었으며, AES 파일 내부에 IV, HMAC 와 같은 각각의 암호화,복호화에 사용되는 정보가 존재

![image](https://github.com/user-attachments/assets/f360122f-ba73-4d6c-b30c-912efcdceeba)

> AES 파일 내부에 암호화 및 복호화 코드 존재, 이를 통해 암호화 된 TCP Data 복호화 코드 작성 가능

| 항목           | 내용                                                                 |
|----------------|----------------------------------------------------------------------|
| 암호화 방식     | AES-CBC 128bit + HMAC-SHA256                                         |
| HMAC 위치      | 맨 앞 32바이트 (HMAC-SHA256)                                         |
| IV 위치        | HMAC 다음 16바이트 (IV)                                              |
| Key 파생 방식  | Rfc2898DeriveBytes(password="1234", salt=static_salt, iterations=50000) |
| Salt 값        | 191, 235, 30, 86, 251, ..., 57, 65 (32바이트 고정)                    |
| 비밀번호       | 1234                                                                  |
| Key 길이       | AES: 16바이트, HMAC: 64바이트                                         |

![image](https://github.com/user-attachments/assets/f83905df-7800-4d7b-95b4-be4b94684f15)

> TCP 페이로드의 처음 4바이트를 사용하여 리틀 엔디안 형식으로 페이로드의 전체 크기를 나타낸다. 이러한 크기 패턴은 Quasar 네트워크 트래픽의 고유한 특징으로, 68 바이트의 경우 크기를 나타내는 4바이트를 제외한 실제 바이트 수는 64바이트이다.

![image](https://github.com/user-attachments/assets/9f6e9603-a358-46fe-b216-e37d1f098730)

> [+] 복호화 결과: Oj
  > 복호화 코드를 작성하여, 해당 페이로드의 TCP Data 를 복호화를 시도, 알 수 없는 문자가 출력되었음

![image](https://github.com/user-attachments/assets/0789fb6d-4c66-4772-a2a5-e20de56f9d93)

> AES 파일 내부에 암호화 및 복호화 코드 존재, 이를 통해 암호화 된 TCP Data 복호화 코드 작성 가능

![image](https://github.com/user-attachments/assets/1a44bb2b-fdd1-4e0f-b56b-d8c15bd9ead8)

> 4바이트의 길이확인 이후 직렬화된 패킷 본문이 오게됨 이 데이터는 NetSerializer 라이브러리를 통해 Ipacket 객체들을 바이너리로 변환한 결과

> 임의의 ASCII가 아니라 의도적으로 삽입된 1~2바이트의 구조 식별자입니다. 특히 참조형(reference type) 데이터에 대해 NetSerializer가 널 여부를 명시하기 위해 사용합니다. 이러한 설계로 수신 측은 객체 존재 여부를 바로 판단할 수 있고, Null인 경우 데이터 스킵,객체인 경우 다음 내용을 해당 타입으로 복원

| 구조 요소              | 예시 값 (hex / ASCII)         | 설명 및 역할 |
|------------------------|-------------------------------|--------------|
| **Null 마커 (N;)**     | `0x4E 0x3B` (`"N;"`)           | 널 객체 표시자. 해당 위치의 객체나 필드가 없음을 나타냄 |
| **Object 마커 (O;)**   | `0x4F 0x3B` (`"O;"`)           | 객체 시작 표시자. 직렬화된 객체 데이터가 존재함을 알리고, 이어지는 데이터가 객체의 타입 및 내용을 의미함. 다음에는 **타입 식별자** 또는 **필드 데이터**가 이어짐 |
| 타입 ID (1 byte)       | `0x4A` (`'J' 문자에 대응`)     | 메시지/객체 타입 식별자. Quasar 클라이언트/서버 간에 약속된 **클래스 ID**이며, `IPacket` 구현 클래스마다 다름 |
| 직렬화된 필드 데이터   | (가변 길이) 예: ...            | 실제 객체의 내용에 해당하는 직렬화된 데이터들. 각 필드는 순서대로 직렬화되며, 필드가 **복합 객체일 경우 다시 `N;` 또는 `O;`** |

![image](https://github.com/user-attachments/assets/a3cfc5c5-251d-4f22-97f5-ea3e3e03cdd0)

## 추가 분석 및 탐지 Signature 적용

![image](https://github.com/user-attachments/assets/0f81df11-5dfa-45b3-9020-87ba1c54bb32)

> TCP Keep-Alive가 주기적으로 발생하고 있으며, 대략 25~26초 간격으로 반복되고 있음. 전부 Len=0, Len=1 로 데이터 교환, Payload 없이 세션 유지 목적의 연결만 유지중. 일반 어플리케이션에서는 볼 수 없는 통신 구조SLE/SRE 값이 함께 동반됨, 이는 RAT 통신의 특성임 세션 유지를 매우 신경씀실제 RAT에 자주 관찰되는 세션 유지형 통신 구조

![image](https://github.com/user-attachments/assets/864e9675-ecba-4a45-bc2f-94322ff29b29)

> D-SACK는 중복 수신된 데이터 존재로 인한 공개 메시지 Application Data 없이 짧은 간격으로 Keep-Alive 와 D-SACK가 발생 Beaconing 의심됨. D-SACK가 반복되며, 짧은 시간내에 주기적으로 발생 이와 함께 Application Data는 존재하지 않음 -> 비정상적 통신 흐름으로 분류

![image](https://github.com/user-attachments/assets/46bc83f7-63d9-4b96-a3e2-6f0812689dd7)

<br>
<hr>
![image](https://github.com/user-attachments/assets/df7850fc-a762-4cca-9e58-9f4ba786140e)

> 짧은 시간 내에 클라이언트에서 서버측으로, 1460 바이트 크기 헤더를 제외한 MTU 1460값을 지속적으로 전달중, 이는 대량의 파일이 유출되는 과정이므로
Flowbits를 연계하면 확실한 파일 유출을 탐지할 수 있음. 


![image](https://github.com/user-attachments/assets/3bed84c3-358e-420a-8555-61091b1cbdaa)

> Remote Shell 연결시 시작부분에서 New Session created 문자열이출력됨. 초기 연결에만 출력되며, 와이어샤크에서 확인시 클라이언트 패킷에서 확인이 가능함

![image](https://github.com/user-attachments/assets/78bde514-3493-46ef-8154-6c2fe95120eb)

> 파일 다운로드와 동일하게 1460 바이트로 대규모 데이터를 전송하며 실시간 요청과 응답값은 이전과 동일한 50 과 40  시그니처가 반복 식별됨


1. Initial access Server -> Client

```
alert tcp any any -> any any (msg:"[Alert] Quasar RAT Initial access Detection Server -> Client Packet"; flow:to_client; flags:PA; flowbits:set,QuasarRAT;
content:“|40 00 00 00|";sid:1000001;rev:1;)
```

2. Initial access Client -> Server

```
alert tcp any any -> any any (msg:"[Alert] Quasar RAT Initial access Detection Server -> Client Packet"; flow:to_client; flags:PA; flowbits:set,QuasarRAT;
content:“|f0 00 00 00|";sid:1000001;rev:1;)
```

3. Health Check

```
alert tcp any any -> any any (msg:"[Alert] Quasar RAT Helath Check Detcetion - ACK";flow:to_client,established;flowbits:isset,helthcheck;dsize:0;threshold: type both, track by_src, count 3, seconds 80;sid:10000004; rev:4;)
```

4. Signatures Code Detection 1

```
alert tcp any any -> any any (msg:"[Alert] Quasar RAT Signatures Code 4";flow:to_client,established;flowbits:isset, QuasarRAT; flags:PA; content:"|40 00 00 00|";depth:4;sid:1000006;rev:6;)
```

5. Signatures Code Detection ２

```
alert tcp any any -> any any (msg:"[Alert] Quasar RAT Signatures Code 5";flow:to_client,established;flowbits:isset, QuasarRAT; flags:PA; content:"|50 00 00 00|";depth:4;sid:1000007;rev:7;)
```

6. Signatures Code Detection 3

```
alert tcp any any -> any any (msg:"[Alert] Quasar RAT Signatures Code 6";flow:to_client,established;flowbits:isset, QuasarRAT; flags:PA; content:"|60 00 00 00|";depth:4;sid:1000008;rev:8;)
```

7. Signatures Code Detection 4

```
alert tcp any any -> any any (msg:"[Alert] Quasar RAT Signatures Code 7";flow:to_client,established;flowbits:isset, QuasarRAT; flags:PA; content:"|70 00 00 00|";depth:4;sid:1000009;rev:9;)
```

8. Signatures Code Detection 5

```
alert tcp any any -> any any (msg:"[Alert] Quasar RAT Signatures Code 8";flow:to_client,established;flowbits:isset, QuasarRAT; flags:PA; content:"|80 00 00 00|";depth:4;sid:1000010;rev:10;)
```


🔴 **참고**  
> Payload 앞의 접두사는 Payload에는 출력되지 않으며, 맨 앞에 붙는 4 Byte의 길이 체크는 Quasar가 명령을 내릴시 응답값에 따라 모든 길이가 다르게 출력되어, 요청값을 제외한 부분에서는 큰 효과가 없다 판단 또한 이 외에 다양한 기능에서 서버에서의 요청값은 40 ~ 80 에서의 기존 시그니처와 동일한 현상이 나타남


# QuasarRAT 1.4.0

![image](https://github.com/user-attachments/assets/819bcfb1-2c93-48f8-999e-bb75ac936940)

> 🔴 ECDHE의 임시 개인키는 메모리에서만 존재하며 세션 종료 시 파기되기 때문에, 서버의 모든 코드, 알고리즘, 고정 키까지 알고 있어도 이 세션에서 사용된 키를 역산할 수 없다. ECDHE를 사용하는 경우, 해당 통신의 암호화는 사실상 실시간 메모리 포렌식 외에는 복호화 불가하다.

![image](https://github.com/user-attachments/assets/3faefd0f-7009-4165-ae77-64d79534b5d9)

> 초기 TLS HandShake 과정 이후 4개의 고정 데이터 교환이 이루어짐 해당 과정인 Victim PC (KR, CN, EN) 3개의 PC에서 동일하게 발생 초기 2개의 패킷은 Server -> Client 로 87 크기의 데이터와 이후 802(803, 809) 크기의 데이터를 전송 그 후 2개의 고정된 87 크기의 데이터를 Client -> Server 방향으로 전송하고 있음. 또한 요청과 요청 사이에 응답이 존재하지 않음． 이는 C2 등록 초기 플로우로 의심된다. 해당 부분이 Server 과 Client 의 초기 연결 부분으로 짐작할 수 있음. 
 > 3 HandShake 과정 이후 바로 TLS HandShake 과정으로 들어가 초기 연결 부분은  짐작은 되나 실제 Suricata 혹은 Snort를 가지고는 탐지 룰을 작성하기 힘듬 TLS Encrypted Application Data 의 암호화된 내용을 Suricata 에서는 복호화가 되지 않기 때문

![image](https://github.com/user-attachments/assets/4f49c55f-4a71-44fc-9136-3d5515ef9f42)
<br><hr>
![image](https://github.com/user-attachments/assets/e47b7620-056f-47b6-b55b-6343855eb89f)

> 다양한 플랫폼(RAT 빌드 방식/OS 등)에서도 공통되는 부분이 존재하며,  붉은색의 데이터의 경우 시그니처일 가능성이 높음, 그 뒤로는  한글/일본어/영문 환경에 따라 문자열 인코딩/길이, 컴퓨터 이름과 같은 환경정보, OS별 시스템정보와 같이 다양한 경우에서 데이터 패킷이 달라질 수 있다.

![image](https://github.com/user-attachments/assets/9c77a852-0d98-492b-8b0b-9c324ac1f0d3)

> TCP Keep-Alive가 주기적으로 발생하고 있으며, 대략 25~26초 간격으로 반복되고 있음.  전부 Len=0, Len=1 로 데이터 교환, Payload 없이 세션 유지 목적의 연결만 유지중. 일반 어플리케이션에서는 볼 수 없는 통신 구조 SLE/SRE 값이 함께 동반됨, 이는 RAT 통신의 특성임 세션 유지를 매우 신경씀 실제 RAT에 자주 관찰되는 세션 유지형 통신 구조

![image](https://github.com/user-attachments/assets/2d4cd082-cfb3-4c7c-ae39-54b4276a3228)

> D-SACK는 중복 수신된 데이터 존재로 인한 공개 메시지 Application Data 없이 짧은 간격으로 Keep-Alive 와 D-SACK가 발생 Beaconing 의심됨. D-SACK가 반복되며, 짧은 시간내에 주기적으로 발생 이와 함께 Application Data는 존재하지 않음 -> 비정상적 통신 흐름으로 분류


> 인증서 Subject 블록의
CN(Common Name) 즉, 인증 대상의 호스트 이름 또는 식별자 이름이 
Quasar Server CA 로 되어 있다.  
O (Organization), OU (Organizational Unit) 필드는 없으며, 해당 인증서는 자체 생성된 셀프사인 인증서로 보인다.







# 참고 문헌
### https://www.cisa.gov/news-events/analysis-reports/ar18-352a#:~:text=first%204%20bytes%20of%20the,payload%20size%20of%2064%20bytes
### https://unit42.paloaltonetworks.com/unit42-downeks-and-quasar-rat-used-in-recent-targeted-attacks-against-governments/#:~:text=Quasar%20contains%20the%20NetSerializer%20library,each%20other%20to%20some%20extent
### https://github.com/quasar/Quasar/tree/v1.3.0.0
### https://asec.ahnlab.com/ko/tag/quasarrat-jp/
### http://www.wins21.co.kr/kor/promotion/information.html?bmain=view&uid=4424&search=%26depth1%3D%26find_field%3Dtitle%26find_word%3DQuasar%26page%3D1
### https://www.uptycs.com/blog/threat-research-report-team/quasar-rat


