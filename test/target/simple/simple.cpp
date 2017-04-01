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
