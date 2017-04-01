WDD는 Record & Replay 기반의 결정적 디버거 입니다.

# 결정적 디버깅? (Deterministic debugging?)
프로그램을 작성하다 보면 버그는 항상 생기게 됩니다. 이런 버그를 잡기 위해 항상  디버깅에 많은 시간을 쓰게 됩니다. 특히 가끔 발생하는 재현이 힘든 버그라면 디버깅 과정이 만만치 않게 됩니다.

만약 어떤 버그라도 항상 재현할 수 있게 된다면 어떨까요?

같은 실행파일이라면 똑같은 환경이라면 매번 실행할 때마다 똑같이 돌아야 할 겁니다. 하지만 유저 입력, 랜덤, 네트워크 패킷 등이 매번 달라지기 때문에 실행할 때마다 달라진 결과를 보게 됩니다.

이런 외부의 영향을 다 기록해 두었다가 프로그램이 필요로 할 때 똑같이 제공해준다면, 항상 똑같은 실행을 보장할 수 있게 됩니다. 버그가 났던 시점의 외부 영향을 똑같이 준다면, 똑같이 버그가 발생하게 되겠죠. (여기서 말하는 외부 영향은 쓰레드의 실행 순서도 포함합니다!)

이미 이런 아이디어로부터 출발한 여러 프로젝트가 있습니다. 대표적으로 [rr (http://rr-project.org/)](http://rr-project.org/)을 들 수 있습니다. 
다만 rr은 리눅스 전용이었기 때문에 이 프로젝트는 rr의 아이디어를 윈도우로 새로 구현한 프로젝트 입니다.

# 예제
![Demo](https://raw.githubusercontent.com/ipkn/wdd/master/doc/wdd_sample.gif)

<details>
<summary>
simple.cpp 소스
</summary>

```cpp
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <random>
#include <iostream>

int main()
{
	time_t now;
	srand(time(&now));

	struct tm* timeinfo = localtime(&now);
	char buffer[80];
	strftime(buffer,sizeof(buffer),"%Y-%m-%d %H:%M:%S",timeinfo);
	std::cout << "Current time: ";
	std::cout << buffer << std::endl << std::endl;
	

	std::cout << "10 random numbers:" << std::endl;
	for(int i = 0; i < 10; i ++)
		std::cout << rand() % 100 << ' ';
	std::cout << std::endl << std::endl;


	std::cout << "10 random numbers from C++11 random_device:" << std::endl;
	std::random_device rd;
	std::uniform_int_distribution<> range(0, 99);

	for(int i = 0; i < 10; i ++)
		std::cout << range(rd) << ' ';
	std::cout << std::endl;
	return 0;
}

```

</details>

예제로 사용한 simple.exe는 현재 시간과 랜덤하게 생성한 값들을 출력하는 프로그램 입니다.  
그냥 simple을 실행했을 때는 매번 시간과 랜덤 값들이 모두 바뀌는걸 확인할 수 있습니다.  
이걸 `wdd record simple.exe` 명령을 통해 실행하면서 그 과정을 기록하였고, 이후의 `wdd replay simple.exe` 에선 시간과 랜덤값이 기록된 값과 똑같이 출력되는걸 확인할 수 있습니다.  
`simple.exe`를 다시 실행하면 다시 달라진 결과값을 볼 수 있죠.

![Demo](https://raw.githubusercontent.com/ipkn/wdd/master/doc/wdd_from_debugger.gif)

디버거를 통해서 동작을 확인해 볼까요?  
time(&now) 코드가 실행되면 현재 시간이 now 변수에 저장되게 됩니다.  
한 줄씩 실행해보면서  현재 시간이 저장되는 now 변수가 같은 값으로 되는걸 확인할 수 있습니다.
 



# 사용법

## 기록하기

```
wdd record yourprogram.exe
```

## 기록된 내용대로 똑같이 실행하기

```
wdd replay yourprogram.exe
```

# 구현 방식
  
<details>
<summary>
자세히 보려면 여길 클릭하세요
</summary>

## 참고사항
물론 아직 완성이 된 프로젝트는 아닙니다. (미완성품을 100% 완성한 척 하는 건 만우절이니까요!)  
기본적인 녹화/재생 기능은 모두 만들어저 있지만, 실제로 기록하는 내용은 예제만 돌 수 있는 정도 만 구현되어 있습니다. Windows를 구성하는 수백개의 시스템콜 중 현재 2개 구현하였습니다. 또한 Windows 버전, 32/64비트 등에 따라 바뀌어야 하는 부분도 존재합니다.  

이번 만우절은 디버거 확장 까지 구현하느라 시간이 절대적으로 모자라서 더 멋있어 보이는 예제를 만드는데 실패했네요.

계속 작업하여 DirectX, socket 등 대부분의 기능을 지원하게 되면, 많은 곳에 활용할 수 있을꺼라 기대합니다. QA들이 wdd를 켠 상태로 테스트 하다 버그를 발생시키면, 따로 재현 방식에 대한 의사소통을 하지 않아도, 프로그래머가 그대로 똑같은 버그를 재현할 수 있게 됩니다. 특이한 실행 패턴을 통해서만 재현되는 버그도 여러번 실행해보면서 상황을 추적해보기 훨씬 용이해지게 됩니다.

## Future Work

Step Back / Reverse Continue 기능을 아시나요? 프로그램이 어느 정도 진행한 다음에 거꾸로 실행하면서 이전 상태로 돌아갈 수 있는 기능도 어렵지 않게 추가할 수 있을 꺼라 생각합니다. 항상 똑같은 상태를 거치며 실행되기 때문이죠. 변수가 이상한 값이 되었을 때, 언제 이상한 값으로 설정되었는지 빠르게 찾을 수 있게됩니다.

## 감사합니다.

저의 "만우절에 거짓말 같을 정도로 그럴싸한 프로그램 만들(어 자랑하)기" 프로젝트에 관심가져주셔서 감사합니다. 호응을 많이해주시면 좀더 흥이 나서 재밌는 장난감을 더 만들게 될꺼라 생각합니다. 리플이든 공유든 많이 해주세요. :)

## rr

자세한 방식에 대해 궁금하시면 [How rr works](http://rr-project.org/rr.html)를 확인해보세요.

</details>
