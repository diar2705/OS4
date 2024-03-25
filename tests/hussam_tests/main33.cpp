
#include <iostream>
#include "../malloc_3.cpp"

#define NUM_TESTS 9

#define RUN_TEST(indx) 		\
	do {			 \
		tests[indx]();	  \
	} while(0)

#define MAX_ALLOC 100000000
#define MMAP_THRESHOLD 131072


void print(void) {
	unsigned num_free_blocks = _num_free_blocks();
	unsigned num_free_bytes = _num_free_bytes();
	unsigned num_allocated_blocks =_num_allocated_blocks();
	unsigned num_allocated_bytes =_num_allocated_bytes();
	unsigned num_beta_bytes =_num_meta_data_bytes();
	unsigned size_meta_data =_size_meta_data();
	std::cout << "num_free_blocks = " << num_free_blocks << std::endl;
	std::cout << "num_free_bytes = " <<  num_free_bytes << std::endl;
	std::cout << "num_allocated_blocks = " << num_allocated_blocks  << std::endl; 
	std::cout << "num_allocated_bytes = " <<  num_allocated_bytes << std::endl; 
	std::cout << "num_beta_bytes = " <<  num_beta_bytes << std::endl; 
	std::cout << "size_meta_data = " <<  size_meta_data << std::endl;
	std::cout << std::endl;  
}


void isAllign(void* addr) {
	if(addr == nullptr) { 
		std::cout << "nullptr was sent." << std::endl;
		return;
	}
	unsigned long num_addr = (unsigned long)(addr);
	if(num_addr % 8 != 0) {
		std::cout << "address " << addr << " is not alligned" << std::endl;
	}
}


void test1() {
	void* p1 = smalloc(1);
	void* p2 = smalloc(2);
	void* p3 = smalloc(10);
	void* p4 = smalloc(20);
	void* p5 = smalloc(30);
	void* p6 = smalloc(40);
	list.printAll();
	list.printFree();
	print();
}



void test2() {
	void* p1 = smalloc(20);
	print();
	sfree(p1);
	list.printAll();
	list.printFree();
	print();
}

void test3() {
	void* p1 = smalloc(10); // 16
	void* p2 = smalloc(1); // 40
	sfree(p1);
	sfree(p2);
	list.printAll();
	list.printFree();
	print();
}


void test4() {
	void* p1 = smalloc(10); // 16
	void* p2 = smalloc(1); // 40
	void* p3 = smalloc(20);
	sfree(p1);
	sfree(p3);
	list.printAll();
	list.printFree();
	print();
	sfree(p2);
	list.printAll();
	list.printFree();
	print();
}


void test5() {
	void* p1 = smalloc(10); // 16
	void* p2 = smalloc(1); // 8
	sfree(p2);
	sfree(p1);
	list.printAll();
	list.printFree();
	print();
}

// not inserted
void test6() {
	void* p1 = smalloc(MMAP_THRESHOLD);
	list.printAll();
	list.printFree();
	print();
	sfree(p1);
	list.printAll();
	list.printFree();
	print();
}

// inserted
void test7() {
	void* p1 = smalloc(1);
	sfree(p1);
	p1 = smalloc(10);
	sfree(p1);
	p1 = smalloc(20);
	list.printAll();
	list.printFree();
	print();
	sfree(p1);
	list.printAll();
	list.printFree();
	print();
}

// inserted
void test8() {
	void* p1 = smalloc(30);
	sfree(p1);
	
	p1 = smalloc(10);

	list.printAll();
	list.printFree();
	print();

	sfree(p1);
	p1 = smalloc(20);
	sfree(p1);

	list.printAll();
	list.printFree();
	print();

}

// inserted
void test9() {
	void* p1 = smalloc(300);
	sfree(p1);
	void* p2 = smalloc(1);
	list.printAll();
	list.printFree();
	print();
}

void (*tests[NUM_TESTS])(void) = {
	test1,
	test2,
	test3,
	test4,
	test5,
	test6,
	test7,
	test8,
	test9
};

int main(int argc,char* argv[]) {
	if(argc != 2) {
		std::cerr << "Invalid Usage - Use: <prog_name> <index>" << std::endl;
		return 1;
	}
	unsigned indx = strtol(argv[1],nullptr,10);
	if(indx >= NUM_TESTS) {
		std::cerr << "Invalid Test Index - Index: {0.." << NUM_TESTS - 1 << "}" << std::endl;
		return 1;
	}
	RUN_TEST(indx);
	return 0;
}

