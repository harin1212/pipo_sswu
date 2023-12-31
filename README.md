# 효율적인 클라우드 빅데이터 암호화를 위한 PIPO-CTR mode python 구현 
### 🥇 2021 PIPO 블록암호 경진대회 - 활용사례 부문 우수상
[기사](https://www.donga.com/news/article/all/20211031/110001646/1)

1) PIPO
   <br>
  PIPO는 Plug-In, Plug-Out, 즉 고차 마스킹 소프트웨어 구현이 효율적인 경량 블록 암호를 일컫는다. 성능 오버헤드를 최소화하기 위해 비선형 연산의 수를 줄이는 것이 PIPO의 목적이며, 이는 곧 효율적인 고차 마스킹 구현에서 가장 중요한 요소임을 알 수 있다. 따라서 많은 경량 블록 암호들은 비선형 함수로 4bit S-box [2,9,13,25,42] 또는 8bit S-box [1,14,40,48,64]를 사용하는 반면에, 순열(R-layer)과 S-box(S-layer) 연산으로 구성된 PIPO는 선형 bit 순열 계층에 적합한 다른 유형의 경량 8bit S-box로 개발하여 사용한다. PIPO 는 다음과 같은 명세 (specification)을 갖는다
 - 키 길이 :128bit / 256 bit
 - 라운드 수 :13 / 17
 - 평문 크기 : 64 bit
 - 암호문 크기 : 64 bit

2) PIPO-CTR mode <br>
  본 구현에서는 PIPO의 구현적 특성에 가장 적합한 CTR 모드를 활용하였다. CTR 모드는 블록암호를 스트림암호화 시키는 암호로 볼 수 있으며, ‘카운터’ 값을 암호화하여 나온 값을 평문과 xor 하여 암호문을 출력한다. 특히 평문 블록의 개수만큼 카운터값을 미리 세팅하여 동시에 암호화할 수 있는 병렬화가 가능하다는 특징을 가진다. <br>
  한편, PIPO는 bitslice 방법을 활용하여 구현을 진행하였는데, 해당 방법은 입력받은 64bit plaintext를 8bit씩 나누어 하위 8bit부터 X[0] ~ X[7] 로 두어 연산이 진행될 수 있는 특징을 가진다. 이를 CTR 모드와 결합하면, 개의 메시지를 암호화는데 있어서, 각 메시지의 하위 8bit를 모아서 X[0]에 저장하고, 그 다음 각 메시지의 8bit를 모아서 X[1]에 저장하고, 이 방법을 반복하여 X[7] 까지 만들게 되면, 각 X[i] 에는  비트가 담기게 된다. 이 X[0] ~X[7]을 이용하여 동시에 암호화가 진행된다면, 더 빠르게 수행할 수 있고, 해당 병렬화 방법을 이용한 CTR 모드는 PIPO의 특성에 의해 가능한 부분이다. 

3) Python을 활용한 PIPO-CRT mode 구현 <br>
 Track 3(PIPO 활용 사례)의 주제는 ‘빅데이터, 클라우드, DB, 모바일 기기 등에 PIPO 활용’이다. 이처럼 대량의 빅데이터를 수집·암호화하기 위해서는 서버의 통신 회선에 신경을 써야 한다. 특히 클라우드 기반의 데이터 관리가 중요하다. 이에 본 팀은 구현 언어의 선택도 많은 영향을 미칠 것으로 판단, 공동 작업과 유지보수가 쉽고 생산성이 높으며 다른 프로그램과의 호환성도 높은 파이썬(Python)을 활용하기로 했다. <br>
 또한, 멀티 코어 및 병렬 처리에 대해 개선이 되는 점 등으로 속도를 올리기가 훨씬 쉬워졌기 때문에 빅데이터에 적합하다고 생각했다. 특히 큰 배열 연산에 강한 점이 PIPO의 병렬 가능성과 관련되어 있어 해당 언어에 확고한 선택을 할 수 있었다. <br>
 다음으로는 ‘활용’에 초점을 맞추었다. 해당 블록 암호를 보다 활용하기 쉽도록 직접 입력이 아닌, 파일 열기·저장 기능을 포함한 GUI를 구현했다. 
