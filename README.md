# How to use?

http(80 포트)통신의 도메인 차단 프로그램
입력한 도메인을 차단해줍니다.

**dependency**

```
sudo apt install libmnl-dev
sudo apt install libnfnetlink-dev
sudo apt install libnetfilter-queue-dev
```
**iptables 설정**
```
iptables -A OUTPUT -j NFQUEUE -lnetfilter_queue
iptables -A INPUT -j NFQUEUE -lnetfilter_queue
```
위 설정이 되어있는지 먼저 확인 해야합니다. (netfilter 큐로 jump시킴)


```.
/실행파일 <차단할 도메인>
ex) ./netfilter naver.com
```

