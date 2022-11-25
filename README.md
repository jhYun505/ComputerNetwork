# 2022 Computer Network
1. ARP Protocol
2. Static Router

# TermProject#2 Static Router
## Goal
다른 네트워크에 있는 호스트와 통신하기 위한 라우터 프로그램

## Static Router
Router에 Routing Table을 수동으로 입력해야하므로 Static Router

## Router의 동작과정
### 패킷 수신
1. 해당 패킷의 IP 목적지 주소를 가져온다.
1. Routing Table을 통해 해당 패킷을 전달할 네트워크 주소를 알아낸다
1. 네트워크 주소로 보내기 위한 인터페이스를 선택
1. 선택된 인터페이스를 통해 Gateway(by Routing Table)로 패킷을 전송한다.
    - Gateway의 IP 주소는 Routing Table을 통해서 알 수 있다.
    - 패킷을 Gateway에 전달하려면 그 Gateway의 MAC 주소를 알아야 한다.
    - MAC 주소는 ARP cache table에서 Gateway 주소에 해당하는 MAC 주소를 가져온다.
    - <b>ARP cache table에 Gateway의 정보가 없다면 ARP 메세지를 통해서 MAC 주소를 알아낸다.</b>
1. 모든 Router가 이 과정을 반복하여 목적지까지 패킷을 전달한다.


## Network Topology
<img width="615" alt="스크린샷 2022-11-22 오후 3 05 38" src="https://user-images.githubusercontent.com/81208791/203237443-19c6b468-56ec-4522-9294-30d6dd238f5c.png">








# TermProject#1 ARP

## ARP Protocol
IP 주소를 이용하여 MAC Address 를 알아내기 위한 프로토콜 
### Basic ARP

### Proxy ARP
### Gratuitous ARP

### TimeOut
- Completed Entry : 20 minutes
- Incomplete Entry : 3 minutes

## 구현 목표
### Layer Structure
![img](https://user-images.githubusercontent.com/81208791/193212564-697f86bb-0696-4ea2-8037-2233dc866bed.png)


### GUI Layout
![image](https://user-images.githubusercontent.com/81208791/196479122-c8ca1960-696e-4700-a992-dcfe503866f2.png)



## ToDo List

### 1. Application Layer
- [x] GUI 생성
- [x] 각 Layer 연결
- [x] cache table update

### 2. ARP Layer
Basic ARP, Proxy ARP, Grauitous ARP에 대한 모든 기능 구성
- [x] ARP_MSG의 구성 요소
- [x] ARP Cache Table 자료 구조 결정
- [x] 각각의 Entry Class로 구성
- [x] ARP_MSG 의 초기화
- [x] Send 함수, Receive 함수 수정
- [x] ARP Request에 대한 응답을 보내는 함수 생성(자기 주소 입력 하고 Swapping하는 등의 과정)
- [x] ARP Layer는 IP Layer와는 단방향 연결, Ethernet Layer과는 양방향 연결)
- [x] TimeOut 관련해서 어떻게 할 것인지? => Timer, TimerTask 이용하여 해결함.


### 3. TCP Layer
- [x] TCP Header 생성
- [x] Send() 함수 생성

### 4. IP Layer
- [x] IP Header 생성
- [x] Send() 함수 생성
- [x] IP 주소는 GUI에 나타나야 하므로 String으로 변경하는 것 => Application Layer에서 진행함

### 5. Ethernet Layer
- [x] 이전 과제 참고해서 필요한 함수들 구현

### 6. 추가 구현(ChatFileDlg)
- [ ] GUI 추가 구현
- [ ] Layer 연결 수정
- [ ] 각각의 Chat/File과 연결

